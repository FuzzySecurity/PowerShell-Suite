function Invoke-Runas {

<#
.SYNOPSIS

    Overview:
    
    Functionally equivalent to Windows "runas.exe", using Advapi32::CreateProcessWithLogonW. Advapi32::GetTokenInformation is not necessary here but was added for reference.
    
    Parameters:

     -User              Specifiy username.
     
     -Password          Specify password.
     
     -Domain            Specify domain. Defaults to localhost if not specified.
     
     -LogonType         dwLogonFlags:
                          0x00000001 --> LOGON_WITH_PROFILE
                                           Log on, then load the user profile in the HKEY_USERS registry
                                           key. The function returns after the profile is loaded.
                                           
                          0x00000002 --> LOGON_NETCREDENTIALS_ONLY (= /netonly)
                                           Log on, but use the specified credentials on the network only.
                                           The new process uses the same token as the caller, but the
                                           system creates a new logon session within LSA, and the process
                                           uses the specified credentials as the default credentials.
     
     -Binary            Full path of the module to be executed.
                       
     -Args              Arguments to pass to the module, e.g. "/c calc.exe". Defaults
                        to $null if not specified.
                       

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
.EXAMPLE
	Start cmd with a local account
	C:\PS> Invoke-Runas -User SomeAccount -Password SomePass -Binary C:\Windows\System32\cmd.exe -LogonType 0x1
	
.EXAMPLE
	Start cmd with remote credentials. Equivalent to "/netonly" in runas.
	C:\PS> Invoke-Runas -User SomeAccount -Password SomePass -Domain SomeDomain -Binary C:\Windows\System32\cmd.exe -LogonType 0x2
#>

	param (
		[Parameter(Mandatory = $True)]
		[string]$User,
		[Parameter(Mandatory = $True)]
		[string]$Password,
		[Parameter(Mandatory = $False)]
		[string]$Domain=".",
		[Parameter(Mandatory = $True)]
		[string]$Binary,
		[Parameter(Mandatory = $False)]
		[string]$Args=$null,
		[Parameter(Mandatory = $True)]
		[string]$LogonType
	)  

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
	}
	
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
		public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars;
		public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow;
		public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	
	[StructLayout(LayoutKind.Sequential, Size=8)]
	public struct LARGE_INTEGER
	{
		public uint LowPart; public int HighPart;
	}
	
	[StructLayout(LayoutKind.Sequential, Size=8)]
	public struct LUID
    {
		public uint LowPart; public int HighPart;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct TOKEN_STATISTICS
	{
		LUID _tokenId; LUID _authenticationId; LARGE_INTEGER _expirationTime; public uint _tokenType;
		public uint _impersonationLevel; public uint _dynamicCharged; public uint _dynamicAvailable;
		public uint _groupCount; public uint _privilegeCount; LUID _modifiedId;
	}
	
	public static class Advapi32
	{
		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
		public static extern bool CreateProcessWithLogonW(
			String userName,
			String domain,
			String password,
			int logonFlags,
			String applicationName,
			String commandLine,
			int creationFlags,
			int environment,
			String currentDirectory,
			ref  STARTUPINFO startupInfo,
			out PROCESS_INFORMATION processInformation);
		
		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
		public static extern bool OpenProcessToken(
			IntPtr ProcessHandle, 
			uint DesiredAccess,
			out IntPtr TokenHandle);
			
		[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
		public static extern bool GetTokenInformation(
			IntPtr TokenHandle,
			uint TokenInformationClass,
			IntPtr TokenInformation,
			uint TokenInformationLength,
			out uint ReturnLength);
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
		
		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(
			int dwDesiredAccess,
			bool bInheritHandle,
			int dwProcessId);
	}
"@
	
	# StartupInfo Struct
	$StartupInfo = New-Object STARTUPINFO
	$StartupInfo.dwFlags = 0x00000001
	$StartupInfo.wShowWindow = 0x0001
	$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
	
	# ProcessInfo Struct
	$ProcessInfo = New-Object PROCESS_INFORMATION
	
	# CreateProcessWithLogonW --> lpCurrentDirectory
	$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
	
	echo "`n[>] Calling Advapi32::CreateProcessWithLogonW"
	$CallResult = [Advapi32]::CreateProcessWithLogonW($User, $Domain, $Password, $LogonType, $Binary, $Args, 0x04000000, $null, $GetCurrentPath, [ref]$StartupInfo, [ref]$ProcessInfo)
	
	if (!$CallResult) {
		$LastError = [Kernel32]::GetLastError()
		echo "[!] Mmm, something went wrong! GetLastError returned: $LastError`n"
	}
	
	else {
		echo "[+] Process Details:"
		Get-Process -Id $ProcessInfo.dwProcessId |ft
		
		# Get proc handle
		echo "[>] Calling Kernel32::OpenProcess"
		$ProcHandle = [Kernel32]::OpenProcess(0x0410, $false, $ProcessInfo.dwProcessId)
		
		if ($ProcHandle -eq 0) {
			# This may fail because of permissions? Just checking in case.
			$LastError = [Kernel32]::GetLastError()
			echo "[!] Mmm, something went wrong! GetLastError returned: $LastError`n"
		}
		
		else {
			echo "[+] Open process handle: $ProcHandle`n"
			
			# Token handle
			echo "[>] Calling Advapi32::OpenProcessToken"
			$hTokenHandle = 0
			$CallResult = [Advapi32]::OpenProcessToken($ProcHandle, 0x00020008, [ref]$hTokenHandle)
			echo "[+] Open access token handle: $hTokenHandle`n"
		
			# Process token stats
			$TokenStats = New-Object TOKEN_STATISTICS
			$TokenStatsStructSize = [System.Runtime.InteropServices.Marshal]::SizeOf($TokenStats)
			$TokenStats = $TokenStats.GetType()
			[IntPtr]$OutBuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenStatsStructSize)
			[UInt32]$StructLength = 0
			
			echo "[>] Calling Advapi32::GetTokenInformation"
			$CallResult = [Advapi32]::GetTokenInformation($hTokenHandle, 10, $OutBuffPtr, $TokenStatsStructSize, [ref]$StructLength)
			$BufferOffset = $OutBuffPtr.ToInt64()
			$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
			echo "[+] TOKEN_STATISTICS Stuct output:"
			[system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr,[type]$TokenStats)
		}
		
	}
	
}