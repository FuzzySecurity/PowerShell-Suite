function Get-SystemModuleInformation {
<#
.SYNOPSIS
	Use NtQuerySystemInformation::SystemModuleInformation to get a list of
	loaded modules, their base address and size (x32/x64).

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	C:\PS> Get-SystemModuleInformation
#>

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct SYSTEM_MODULE_INFORMATION
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
		public UIntPtr[] Reserved;
		public IntPtr ImageBase;
		public UInt32 ImageSize;
		public UInt32 Flags;
		public UInt16 LoadOrderIndex;
		public UInt16 InitOrderIndex;
		public UInt16 LoadCount;
		public UInt16 ModuleNameOffset;
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
		internal Char[] _ImageName;
		public String ImageName {
			get {
				return new String(_ImageName).Split(new Char[] {'\0'}, 2)[0];
			}
		}
	}

	public static class Ntdll
	{
		[DllImport("ntdll.dll")]
		public static extern int NtQuerySystemInformation(
			int SystemInformationClass,
			IntPtr SystemInformation,
			int SystemInformationLength,
			ref int ReturnLength);
	}
"@

	echo "`n[+] Calling NtQuerySystemInformation::SystemModuleInformation"

	[int]$BuffPtr_Size = 0
	while ($true) {
		[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
		$SystemInformationLength = New-Object Int
	
		# SystemModuleInformation Class = 11
		$CallResult = [Ntdll]::NtQuerySystemInformation(11, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)
		
		# STATUS_INFO_LENGTH_MISMATCH
		if ($CallResult -eq 0xC0000004) {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
			[int]$BuffPtr_Size = [System.Math]::Max($BuffPtr_Size,$SystemInformationLength)
		}
		# STATUS_SUCCESS
		elseif ($CallResult -eq 0x00000000) {
			echo "[?] Success, allocated $BuffPtr_Size byte result buffer"
			break
		}
		# Probably: 0xC0000005 -> STATUS_ACCESS_VIOLATION
		else {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
			echo "[!] Error, NTSTATUS Value: $('{0:X}' -f ($CallResult))`n"
			return
		}
	}

	$SYSTEM_MODULE_INFORMATION = New-Object SYSTEM_MODULE_INFORMATION
	$SYSTEM_MODULE_INFORMATION = $SYSTEM_MODULE_INFORMATION.GetType()
	if ([System.IntPtr]::Size -eq 4) {
		$SYSTEM_MODULE_INFORMATION_Size = 284
	} else {
		$SYSTEM_MODULE_INFORMATION_Size = 296
	}

	$BuffOffset = $BuffPtr.ToInt64()
	$HandleCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)
	$BuffOffset = $BuffOffset + [System.IntPtr]::Size
	echo "[?] Result buffer contains $HandleCount SystemModuleInformation objects"

	$SystemModuleArray = @()
	for ($i=0; $i -lt $HandleCount; $i++){
		$SystemPointer = New-Object System.Intptr -ArgumentList $BuffOffset
		$Cast = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SYSTEM_MODULE_INFORMATION)
		
		$HashTable = @{
			ImageName = $Cast.ImageName
			ImageBase = if ([System.IntPtr]::Size -eq 4) {"0x$('{0:X}' -f $($Cast.ImageBase).ToInt32())"} else {"0x$('{0:X}' -f $($Cast.ImageBase).ToInt64())"}
			ImageSize = "0x$('{0:X}' -f $Cast.ImageSize)"
		}
		
		$Object = New-Object PSObject -Property $HashTable
		$SystemModuleArray += $Object
	
		$BuffOffset = $BuffOffset + $SYSTEM_MODULE_INFORMATION_Size
	}

	$SystemModuleArray|Select ImageBase,ImageSize,ImageName |ft -Autosize

	# Free SystemModuleInformation array
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
}