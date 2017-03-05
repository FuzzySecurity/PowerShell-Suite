function Get-CRC32 {
<#
.SYNOPSIS
	Simple wrapper for undocumented RtlComputeCrc32 function.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER InitialCRC
	Optional initial CRC value to start with. Supply 0 initially.

.PARAMETER Buffer
	Byte array to compute the CRC32 of.

.EXAMPLE
	# Example from string
	C:\PS> $String = [System.Text.Encoding]::ASCII.GetBytes("Testing!")
	C:\PS> Get-CRC32 -Buffer $String
	C:\PS> 2392247274
#>

	param(
		[Parameter(Mandatory = $False)]
		[Int]$InitialCRC = 0,
		[Parameter(Mandatory = $True)]
		[Byte[]]$Buffer
    )

	Add-Type -TypeDefinition @"
		using System;
		using System.Diagnostics;
		using System.Runtime.InteropServices;
		using System.Security.Principal;
	
		public static class CRC32
		{
			[DllImport("ntdll.dll")]
			public static extern UInt32 RtlComputeCrc32(
				UInt32 InitialCrc,
				Byte[] Buffer,
				Int32 Length);
		}
"@
	
	
	[CRC32]::RtlComputeCrc32($InitialCRC, $Buffer, $Buffer.Length)
}