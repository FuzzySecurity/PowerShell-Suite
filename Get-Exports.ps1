function Get-Exports {
<#
.SYNOPSIS
Get-Exports, fetches DLL exports and optionally provides
C++ wrapper output (idential to ExportsToC++ but without
needing VS and a compiled binary). To do this it reads DLL
bytes into memory and then parses them (no LoadLibraryEx).
Because of this you can parse x32/x64 DLL's regardless of
the bitness of PowerShell.

.DESCRIPTION
Author: Ruben Boonen (@FuzzySec)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.PARAMETER DllPath

Absolute path to DLL.

.PARAMETER CustomDll

Absolute path to output file.

.EXAMPLE
C:\PS> Get-Exports -DllPath C:\Some\Path\here.dll

.EXAMPLE
C:\PS> Get-Exports -DllPath C:\Some\Path\here.dll -ExportsToCpp C:\Some\Out\File.txt
#>
	param (
        [Parameter(Mandatory = $True)]
		[string]$DllPath,
		[Parameter(Mandatory = $False)]
		[string]$ExportsToCpp
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct IMAGE_EXPORT_DIRECTORY
	{
		public UInt32 Characteristics;
		public UInt32 TimeDateStamp;
		public UInt16 MajorVersion;
		public UInt16 MinorVersion;
		public UInt32 Name;
		public UInt32 Base;
		public UInt32 NumberOfFunctions;
		public UInt32 NumberOfNames;
		public UInt32 AddressOfFunctions;
		public UInt32 AddressOfNames;
		public UInt32 AddressOfNameOrdinals;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct IMAGE_SECTION_HEADER
	{
		public String Name;
		public UInt32 VirtualSize;
		public UInt32 VirtualAddress;
		public UInt32 SizeOfRawData;
		public UInt32 PtrToRawData;
		public UInt32 PtrToRelocations;
		public UInt32 PtrToLineNumbers;
		public UInt16 NumOfRelocations;
		public UInt16 NumOfLines;
		public UInt32 Characteristics;
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern IntPtr LoadLibraryEx(
			String lpFileName,
			IntPtr hReservedNull,
			UInt32 dwFlags);
	}
"@

	# Load the DLL into memory so we can refference it like LoadLibrary
	$FileBytes = [System.IO.File]::ReadAllBytes($DllPath)
	[IntPtr]$HModule = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FileBytes.Length)
	[System.Runtime.InteropServices.Marshal]::Copy($FileBytes, 0, $HModule, $FileBytes.Length)

	# Some Offsets..
	$PE_Header = [Runtime.InteropServices.Marshal]::ReadInt32($HModule.ToInt64() + 0x3C)
	$Section_Count = [Runtime.InteropServices.Marshal]::ReadInt16($HModule.ToInt64() + $PE_Header + 0x6)
	$Optional_Header_Size = [Runtime.InteropServices.Marshal]::ReadInt16($HModule.ToInt64() + $PE_Header + 0x14)
	$Optional_Header = $HModule.ToInt64() + $PE_Header + 0x18

	# We need some values from the Section table to calculate RVA's
	$Section_Table = $Optional_Header + $Optional_Header_Size
	$SectionArray = @()
	for ($i; $i -lt $Section_Count; $i++) {
		$HashTable = @{
			VirtualSize = [Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0x8)
			VirtualAddress = [Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0xC)
			PtrToRawData = [Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0x14)
		}
		$Object = New-Object PSObject -Property $HashTable
		$SectionArray += $Object
		
		# Increment $Section_Table offset by Section size
		$Section_Table = $Section_Table + 0x28
	}

	# Helper function for dealing with on-disk PE offsets.
	# Adapted from @mattifestation:
	# https://github.com/mattifestation/PowerShellArsenal/blob/master/Parsers/Get-PE.ps1#L218
	function Convert-RVAToFileOffset($Rva, $SectionHeaders) {
		foreach ($Section in $SectionHeaders) {
			if (($Rva -ge $Section.VirtualAddress) -and
				($Rva-lt ($Section.VirtualAddress + $Section.VirtualSize))) {
				return [IntPtr] ($Rva - ($Section.VirtualAddress - $Section.PtrToRawData))
			}
		}
		# Pointer did not fall in the address ranges of the section headers
		echo "Mmm, pointer did not fall in the PE range.."
	}

	# Read Magic UShort to determin x32/x64
	if ([Runtime.InteropServices.Marshal]::ReadInt16($Optional_Header) -eq 0x010B) {
		echo "`n[?] 32-bit Image!"
		# IMAGE_DATA_DIRECTORY[0] -> Export
		$Export = $Optional_Header + 0x60
	} else {
		echo "`n[?] 64-bit Image!"
		# IMAGE_DATA_DIRECTORY[0] -> Export
		$Export = $Optional_Header + 0x70
	}

	# Convert IMAGE_EXPORT_DIRECTORY[0].VirtualAddress to file offset!
	$ExportRVA = Convert-RVAToFileOffset $([Runtime.InteropServices.Marshal]::ReadInt32($Export)) $SectionArray

	# Cast offset as IMAGE_EXPORT_DIRECTORY
	$OffsetPtr = New-Object System.Intptr -ArgumentList $($HModule.ToInt64() + $ExportRVA)
	$IMAGE_EXPORT_DIRECTORY = New-Object IMAGE_EXPORT_DIRECTORY
	$IMAGE_EXPORT_DIRECTORY = $IMAGE_EXPORT_DIRECTORY.GetType()
	$EXPORT_DIRECTORY_FLAGS = [system.runtime.interopservices.marshal]::PtrToStructure($OffsetPtr, [type]$IMAGE_EXPORT_DIRECTORY)

	# Print the in-memory offsets!
	echo "`n[>] Time Stamp: $([timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($EXPORT_DIRECTORY_FLAGS.TimeDateStamp)))"
	echo "[>] Function Count: $($EXPORT_DIRECTORY_FLAGS.NumberOfFunctions)"
	echo "[>] Named Functions: $($EXPORT_DIRECTORY_FLAGS.NumberOfNames)"
	echo "[>] Ordinal Base: $($EXPORT_DIRECTORY_FLAGS.Base)"
	echo "[>] Function Array RVA: 0x$('{0:X}' -f $EXPORT_DIRECTORY_FLAGS.AddressOfFunctions)"
	echo "[>] Name Array RVA: 0x$('{0:X}' -f $EXPORT_DIRECTORY_FLAGS.AddressOfNames)"
	echo "[>] Ordinal Array RVA: 0x$('{0:X}' -f $EXPORT_DIRECTORY_FLAGS.AddressOfNameOrdinals)"

	# Get equivalent file offsets!
	$ExportFunctionsRVA = Convert-RVAToFileOffset $EXPORT_DIRECTORY_FLAGS.AddressOfFunctions $SectionArray
	$ExportNamesRVA = Convert-RVAToFileOffset $EXPORT_DIRECTORY_FLAGS.AddressOfNames $SectionArray
	$ExportOrdinalsRVA = Convert-RVAToFileOffset $EXPORT_DIRECTORY_FLAGS.AddressOfNameOrdinals $SectionArray

	# Loop exports
	$ExportArray = @()
	for ($i=0; $i -lt $EXPORT_DIRECTORY_FLAGS.NumberOfNames; $i++){
		# Calculate function name RVA
		$FunctionNameRVA = Convert-RVAToFileOffset $([Runtime.InteropServices.Marshal]::ReadInt32($HModule.ToInt64() + $ExportNamesRVA + ($i*4))) $SectionArray
		$HashTable = @{
			FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($HModule.ToInt64() + $FunctionNameRVA)
			ImageRVA = echo "0x$("{0:X8}" -f $([Runtime.InteropServices.Marshal]::ReadInt32($HModule.ToInt64() + $ExportFunctionsRVA + ($i*4))))"
			Ordinal = [Runtime.InteropServices.Marshal]::ReadInt16($HModule.ToInt64() + $ExportOrdinalsRVA + ($i*2)) + $EXPORT_DIRECTORY_FLAGS.Base
		}
		$Object = New-Object PSObject -Property $HashTable
		$ExportArray += $Object
	}

	# Print export object
	$ExportArray |Sort-Object Ordinal

	# Optionally write ExportToC++ wrapper output
	if ($ExportsToCpp) {
		foreach ($Entry in $ExportArray) {
			Add-Content $ExportsToCpp "#pragma comment (linker, '/export:$($Entry.FunctionName)=[FORWARD_DLL_HERE].$($Entry.FunctionName),@$($Entry.Ordinal)')"
		}
	}

	# Free buffer
	[Runtime.InteropServices.Marshal]::FreeHGlobal($HModule)
}
