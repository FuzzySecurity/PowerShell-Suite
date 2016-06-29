function Detect-Debug {
<#
.SYNOPSIS

	Use several techniques to detect the presence of a debugger. I realise 
	this does not make much sense from PowerShell (you may as well detect a
	text editor..) but there you go :)!

    Notes:

	* Using Kernel32::OutputDebugString does not appear to work in PowerShell.
	  In theory calling OutputDebugString, without a debugger attached, should
	  generate an error code. This lets you check if LastError has been
	  overwritten. Test case below:

	  [Kernel32]::SetLastError(0xb33f) # Set fake LastError
	  [Kernel32]::OutputDebugString("Hello Debugger!")
	  if ([Kernel32]::GetLastError() -eq 0xb33f) {
		echo "[?] OutputDebugString: Detected"
	  } else {
		echo "[?] OutputDebugString: False"
	  }

	* For bonus points call NtSetInformationThread::ThreadHideFromDebugger,
	  this will detach a thread from the debugger essentially making it
	  invisible! Test case below:
	  
	  $ThreadHandle = [Kernel32]::GetCurrentThread()
	  $CallResult = [Ntdll]::NtSetInformationThread($ThreadHandle, 17, [ref][IntPtr]::Zero, 0)
	  
	* I may update with some extra techniques (eg: Trap Flag) if I can find a
	  convenient way to run inline assembly (C style __asm). As it stands, it
	  is possible but cumbersome (= laziness prevails!).

    References:
	
	*  Anti Reverse Engineering Protection Techniques:
	   https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software
	*  Windows Anti-Debug Reference:
	   http://www.symantec.com/connect/articles/windows-anti-debug-reference

.DESCRIPTION

	Author: Ruben Boonen (@FuzzySec)
	Blog: http://www.fuzzysecurity.com/
	License: BSD 3-Clause
	Required Dependencies: PowerShell v2+
	Optional Dependencies: None
    
.EXAMPLE

	C:\PS> Detect-Debug
#>
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
	{
		public Byte DebuggerEnabled;
		public Byte DebuggerNotPresent;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct _PROCESS_BASIC_INFORMATION
	{
		public IntPtr ExitStatus;
		public IntPtr PebBaseAddress;
		public IntPtr AffinityMask;
		public IntPtr BasePriority;
		public UIntPtr UniqueProcessId;
		public IntPtr InheritedFromUniqueProcessId;
	}
	
	[StructLayout(LayoutKind.Explicit, Size = 192)]
	public struct PEB_BeingDebugged_NtGlobalFlag
	{
		[FieldOffset(2)]
		public Byte BeingDebugged;
		[FieldOffset(104)]
		public UInt32 NtGlobalFlag32;
		[FieldOffset(188)]
		public UInt32 NtGlobalFlag64;
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern bool IsDebuggerPresent();
	
		[DllImport("kernel32.dll")]
		public static extern bool CheckRemoteDebuggerPresent(
			IntPtr hProcess,
			out bool pbDebuggerPresent);
	
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern void OutputDebugString(string lpOutputString);
	
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool CloseHandle(IntPtr hObject);
	
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern IntPtr GetCurrentThread();
	
		[DllImport("kernel32.dll")]
		public static extern void SetLastError(int dwErrorCode);
	
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
	}
	
	public static class Ntdll
	{
		[DllImport("ntdll.dll")]
		public static extern int NtQuerySystemInformation(
			int SystemInformationClass,
			ref _SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInformation,
			int SystemInformationLength,
			ref int ReturnLength);
	
		[DllImport("ntdll.dll")]
		public static extern int NtQueryInformationProcess(
			IntPtr processHandle, 
			int processInformationClass,
			ref _PROCESS_BASIC_INFORMATION processInformation,
			int processInformationLength,
			ref int returnLength);
	
		[DllImport("ntdll.dll")]
		public static extern int NtSetInformationThread(
			IntPtr ThreadHandle, 
			int ThreadInformationClass,
			ref IntPtr ThreadInformation,
			int ThreadInformationLength);
	}
"@
	
	echo "`n[+] Detect Kernel-Mode Debugging"
	
	# (1) _SYSTEM_KERNEL_DEBUGGER_INFORMATION, kernel debugger detection
	#-----------
	$SYSTEM_KERNEL_DEBUGGER_INFORMATION = New-Object _SYSTEM_KERNEL_DEBUGGER_INFORMATION
	$SYSTEM_KERNEL_DEBUGGER_INFORMATION_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($SYSTEM_KERNEL_DEBUGGER_INFORMATION)
	$SystemInformationLength = New-Object Int
	$CallResult = [Ntdll]::NtQuerySystemInformation(35, [ref]$SYSTEM_KERNEL_DEBUGGER_INFORMATION, $SYSTEM_KERNEL_DEBUGGER_INFORMATION_Size, [ref]$SystemInformationLength)
	if ($SYSTEM_KERNEL_DEBUGGER_INFORMATION.DebuggerEnabled -And !$SYSTEM_KERNEL_DEBUGGER_INFORMATION.DebuggerNotPresent) {
		echo "    [?] SystemKernelDebuggerInformation: Detected"
	} else {
		echo "    [?] SystemKernelDebuggerInformation: False"
	}
	
	echo "`n[+] Detect User-Mode Debugging"
	# (2) CloseHandle exception check, generates exception in debugger
	#-----------
	$hObject = 0x1 # Invalid handle
	$Exception = "False"
	try {
		$CallResult = [Kernel32]::CloseHandle($hObject)
	} catch {
		$Exception = "Detected"
	} echo "    [?] CloseHandle Exception: $Exception"
	
	# (3) IsDebuggerPresent
	#-----------
	if ([Kernel32]::IsDebuggerPresent()) {
		echo "    [?] IsDebuggerPresent: Detected"
	} else {
		echo "    [?] IsDebuggerPresent: False"
	}
	
	# (4) CheckRemoteDebuggerPresent --> calls NtQueryInformationProcess::ProcessDebugPort under the hood
	#-----------
	$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
	$DebuggerPresent = [IntPtr]::Zero
	$CallResult = [Kernel32]::CheckRemoteDebuggerPresent($ProcHandle, [ref]$DebuggerPresent)
	if ($DebuggerPresent) {
		echo "    [?] CheckRemoteDebuggerPresent: Detected"
	} else {
		echo "    [?] CheckRemoteDebuggerPresent: False"
	}
	
	# (5-6) PEB BeingDebugged & NtGlobalFlag checks
	#-----------
	$PROCESS_BASIC_INFORMATION = New-Object _PROCESS_BASIC_INFORMATION
	$PROCESS_BASIC_INFORMATION_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($PROCESS_BASIC_INFORMATION)
	$returnLength = New-Object Int
	$CallResult = [Ntdll]::NtQueryInformationProcess($ProcHandle, 0, [ref]$PROCESS_BASIC_INFORMATION, $PROCESS_BASIC_INFORMATION_Size, [ref]$returnLength)
	
	# Lazy PEB parsing
	$PEB_BeingDebugged_NtGlobalFlag = New-Object PEB_BeingDebugged_NtGlobalFlag
	$PEB_BeingDebugged_NtGlobalFlag_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($PEB_BeingDebugged_NtGlobalFlag)
	$PEB_BeingDebugged_NtGlobalFlag = $PEB_BeingDebugged_NtGlobalFlag.GetType()
	
	$BufferOffset = $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64()
	$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
	$PEBFlags = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$PEB_BeingDebugged_NtGlobalFlag)
	
	if ($PEBFlags.BeingDebugged -eq 1) {
		echo "    [?] PEB!BeingDebugged: Detected"
	} else {
		echo "    [?] PEB!BeingDebugged: False"
	}
	
	# Our struct records what would be NtGlobalFlag for x32/x64
	if ($PEBFlags.NtGlobalFlag32 -eq 0x70 -Or $PEBFlags.NtGlobalFlag64 -eq 0x70) {
		echo "    [?] PEB!NtGlobalFlag: Detected"
	} else {
		echo "    [?] PEB!NtGlobalFlag: False"
	}
	
	# (7) Debug parent from child
	#-----------
	$ScriptBlock = {
		Add-Type -TypeDefinition @"
		using System;
		using System.Diagnostics;
		using System.Runtime.InteropServices;
		using System.Security.Principal;
		
		public static class Kernel32
		{
			[DllImport("kernel32.dll")]
			public static extern bool DebugActiveProcess(int dwProcessId);
			
			[DllImport("kernel32")]
			public static extern bool DebugActiveProcessStop(int ProcessId);
		}
"@
		$OwnPID = [System.Diagnostics.Process]::GetCurrentProcess().Id
		$ParentPID = (Get-WmiObject -Query "SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = $OwnPID").ParentProcessId
		if (![Kernel32]::DebugActiveProcess($ParentPID)) {
			echo "    [?] DebugSelf: Detected`n"
		} else {
			echo "    [?] DebugSelf: False`n"
			$CallResult = [Kernel32]::DebugActiveProcessStop($ParentPID)
		}
	}
	
	# Start-Job launches $ScriptBlock as child process
	Start-Job -Name Self_Debug -ScriptBlock $ScriptBlock| Out-Null
	Wait-Job -Name Self_Debug| Out-Null
	Receive-Job -Name Self_Debug
	Remove-Job -Name Self_Debug
}