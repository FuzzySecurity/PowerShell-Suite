function Get-TokenPrivs {
<#
.SYNOPSIS
	Open a handle to a process and use Advapi32::GetTokenInformation
	to list the privileges associated with the process token.

	Notes:

	* You can only get token privileges for a process you own or
	  belonging to a lower privilege user account. In general, regular
	  users can only access their own tokens while Administrators can
	  access all process tokens including those belonging to
	  "NT AUTHORITY\SYSTEM".

	* There are some quirks here, certain processes allow you to open
	  a handle to the process but not to the process token. Most notably,
	  almost all "NT AUTHORITY\* SERVICE" are like this. Additionally,
	  GetLastError sometimes erroneously reports the error as 203 (0xCB)
	  ERROR_ENVVAR_NOT_FOUND instead of 5 (0x5) ERROR_ACCESS_DENIED. To
	  get the token privileges for these processes the function must be
	  run as SYSTEM.
	  
	* Some processes are protected, like PID 4 (System), and prevent
	  access even when running as SYSTEM.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	C:\PS> Get-TokenPrivs -ProcID 1234

#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[int]$ProcID
	)
	
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct LUID
	{
		public uint LowPart;
		public int HighPart;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct LUID_AND_ATTRIBUTES
	{
		public LUID Luid;
		public UInt32 Attributes;
	}
	
	public struct TOKEN_PRIVILEGES
	{
		public UInt32 PrivilegeCount;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
		public LUID_AND_ATTRIBUTES[] Privileges;
	}
	
	public static class Advapi32
	{
		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]		
		public static extern bool OpenProcessToken(		
			IntPtr ProcessHandle, 		
			uint DesiredAccess,		
			out IntPtr TokenHandle);
	
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool GetTokenInformation(
			IntPtr TokenHandle,
			uint TokenInformationClass,
			IntPtr TokenInformation,
			int TokenInformationLength,
			ref int ReturnLength);
	
		[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool LookupPrivilegeName(
			string lpSystemName,
			IntPtr lpLuid,
			System.Text.StringBuilder lpName,
			ref int cchName);
	}
	
	public static class Kernel32
	{
	
		[DllImport("kernel32.dll")]		
		public static extern IntPtr OpenProcess(		
			int dwDesiredAccess,		
			bool bInheritHandle,		
			int dwProcessId);
	
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
	}
"@

	# Check if the user is running as Admin
	$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')

	# Make sure the PID exists
	if (!$(get-process -Id $ProcID -ErrorAction SilentlyContinue)) {
		echo "`n[!] The specified PID doesn't exist, exiting..`n"
		Return
	} else {
		echo "`n[?] PID $ProcID --> $((Get-Process -Id $ProcID).ProcessName)"
	}

	# Get handle to the process
	$ProcHandle = [Kernel32]::OpenProcess(0x0410, $false, $ProcID)
	if ($ProcHandle -eq 0) {
		if ($IsAdmin) {
			echo "[!] Unable to open process (as Administrator), this may require SYSTEM access.`n"
		} else {
			echo "[!] Unable to open process, this may require Administrator/SYSTEM access.`n"
		} return
	} echo "[+] Process handle: $ProcHandle"
	
	# Get handle to the process token
	$hTokenHandle = 0
	$CallResult = [Advapi32]::OpenProcessToken($ProcHandle, 0x00020008, [ref]$hTokenHandle)
	if ($CallResult -eq 0) {
		echo "[!] Unable to open process token, this may require SYSTEM access.`n"
		return
	} echo "[+] Token handle: $hTokenHandle"
	
	# Call GetTokenInformation with TokenInformationClass = 3 (TokenPrivileges)
	[int]$Length = 0
	$CallResult = [Advapi32]::GetTokenInformation($hTokenHandle, 3, [IntPtr]::Zero, $Length, [ref]$Length)
	
	# After we get the buffer length alloc and call again
	[IntPtr]$TokenInformation = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Length)
	$CallResult = [Advapi32]::GetTokenInformation($hTokenHandle, 3, $TokenInformation, $Length, [ref]$Length)
	
	# Read dword at $TokenInformation to get privilege count
	$BuffOffset = $TokenInformation.ToInt64()
	$PrivCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)
	$BuffOffset = $BuffOffset + 4 # Offset privilege count
	"[+] Token has $PrivCount privileges:"
	
	# Create LUID and attributes object
	$LUID_AND_ATTRIBUTES = New-Object LUID_AND_ATTRIBUTES
	$LUID_AND_ATTRIBUTES_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($LUID_AND_ATTRIBUTES)
	$LUID_AND_ATTRIBUTES = $LUID_AND_ATTRIBUTES.GetType()
	
	# Loop $BuffOffset ==> PtrToStructure $LUID_AND_ATTRIBUTES -> StructureToPtr $LUID_AND_ATTRIBUTES.Luid
	$LuidPrivilegeArray = @()
	for ($i=0; $i -lt $PrivCount; $i++) {

		# Cast IntPtr to LUID_AND_ATTRIBUTES
		$PrivPointer = New-Object System.Intptr -ArgumentList $BuffOffset
		$Cast = [system.runtime.interopservices.marshal]::PtrToStructure($PrivPointer,[type]$LUID_AND_ATTRIBUTES)

		# Cast LUID sub-struct back to IntPtr
		$LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf($Cast.Luid)
		[IntPtr]$lpLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
		[system.runtime.interopservices.marshal]::StructureToPtr($Cast.Luid, $lpLuid, $true)

		# Call to get lpName length, create System.Text.StringBuilder object & call again
		[int]$Length = 0
		$CallResult = [Advapi32]::LookupPrivilegeName($null, $lpLuid, $null, [ref]$Length)
		$lpName = New-Object -TypeName System.Text.StringBuilder
		$lpName.EnsureCapacity($Length+1) |Out-Null
		$CallResult = [Advapi32]::LookupPrivilegeName($null, $lpLuid, $lpName, [ref]$Length)

		# Create result object
		$HashTable = @{
			LUID = $Cast.Luid.LowPart
			Privilege = $lpName
		}
		$Object = New-Object PSObject -Property $HashTable
		$LuidPrivilegeArray += $Object
		
		# Free $LuidSize & increment $BuffOffset
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($lpLuid)
		$BuffOffset = $BuffOffset + $LUID_AND_ATTRIBUTES_Size

	}
	
	# Print and AutoSize
	$LuidPrivilegeArray |Format-Table -AutoSize
	
	# Free $TokenInformation
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenInformation)

}