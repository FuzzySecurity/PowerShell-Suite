function Trace-Execution {
<#
.SYNOPSIS

	Uses the Capstone engine to recursively disassemble a PE (x32/x64) from
	it's entry point, effectively "following" execution flow. The following
	rules are observed:

	- jmp's are taken if they fall in the PE address space
	- call's are taken if they fall in the PE address space
	- ret's are taken and use the return address stored by call instructions
	- indirect call/jmp's are not taken
	- conditional jmp's are not taken
	- call/jmp's which reference a register are not taken
	
	There are many many edge cases here which can make disassembly unreliable.
	As a general rule, the more addresses you disassemble, the less trustworthy
	the output is. The call table can be used as a reference to gauge the veracity
	of the output.

	Since disassembly is static, working of a byte array, x32/x64 PE's can be
	disassembled regardless of the bitness of PowerShell.

.DESCRIPTION

	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: Get-CapstoneDisassembly
	Optional Dependencies: None

.PARAMETER Path

	Path to the PE on disk.

.PARAMETER InstructionCount

	Number of instructions to disassemble.

.EXAMPLE
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
#>
	param (
        [Parameter(Mandatory = $True)]
		[string]$Path,
		[Parameter(Mandatory = $True)]
		[Int]$InstructionCount
	)

	# Make sure the Capstone module is loaded
	if (![bool](Get-Command Get-CapstoneDisassembly -errorAction SilentlyContinue)) {
		echo "`n[!] Get-CapstoneDisassembly not found, quitting.."
		echo "    -> https://github.com/FuzzySecurity/CapstoneKeystone-PowerShell`n"
		Return
	}
	
	# Returns $InMemoryEntryPoint, $ImageBase, $SectionArray and $x32/!$x32
	function Return-PeInfo($MemPointer) {
		# Some Offsets..
		$PE_Header = [Runtime.InteropServices.Marshal]::ReadInt32($MemPointer.ToInt64() + 0x3C)
		$Section_Count = [Runtime.InteropServices.Marshal]::ReadInt16($MemPointer.ToInt64() + $PE_Header + 0x6)
		$Optional_Header_Size = [Runtime.InteropServices.Marshal]::ReadInt16($MemPointer.ToInt64() + $PE_Header + 0x14)
		$Optional_Header = $MemPointer.ToInt64() + $PE_Header + 0x18
		$Script:InMemoryEntryPoint = [Runtime.InteropServices.Marshal]::ReadInt32($Optional_Header + 0x10)
		if ([Runtime.InteropServices.Marshal]::ReadInt16($Optional_Header) -eq 0x010B) {
			echo "`n[>] 32-bit Image!"
			$Script:ImageBase = [Runtime.InteropServices.Marshal]::ReadInt32($Optional_Header + 0x1C)
			$Script:x32 = 1
		} else {
			echo "`n[>] 64-bit Image!"
			$Script:ImageBase = [Runtime.InteropServices.Marshal]::ReadInt64($Optional_Header + 0x18)
		}
		$Section_Table = $Optional_Header + $Optional_Header_Size
		$SectionArray = @()
		for ($i; $i -lt $Section_Count; $i++) {
			$HashTable = @{
				VirtualSize = [Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0x8)
				VirtualAddress = [Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0xC)
				PtrToRawData = [Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0x14)
				Characteristics = $($CharVal = "{0:X8}" -f $([Runtime.InteropServices.Marshal]::ReadInt32($Section_Table + 0x24)); if ($CharVal[0] -eq "2"){echo "x"}; if ($CharVal[0] -eq "4"){echo "r"}; if ($CharVal[0] -eq "8"){echo "w"}; if ($CharVal[0] -eq "6"){echo "rx"}; if ($CharVal[0] -eq "C"){echo "rw"})
			}
			$Object = New-Object PSObject -Property $HashTable
			$SectionArray += $Object
			
			# Increment $Section_Table offset by Section size
			$Section_Table = $Section_Table + 0x28
		}
		$Script:SectionArray = $SectionArray
	}
	
	# Helper function for dealing with on-disk PE offsets.
	# Adapted from @mattifestation:
	# https://github.com/mattifestation/PowerShellArsenal/blob/master/Parsers/Get-PE.ps1#L218
	function Convert-RVAToFileOffset($Rva, $SectionHeaders) {
		foreach ($Section in $SectionHeaders) {
			if (($Rva -ge $Section.VirtualAddress) -and
				($Rva-lt ($Section.VirtualAddress + $Section.VirtualSize))) {
				return [UInt64] ($Rva - ($Section.VirtualAddress - $Section.PtrToRawData))
			}
		}
		# Pointer did not fall in the address ranges of the section headers
		echo "Mmm, pointer did not fall in the PE range.."
	}
	
	function Follow-ASM($Address, $MemEP, $ImageBase) {
		# Result variables
		$ETrace = @()
		$CallTrace = @()
		$RetFIFO = New-Object System.Collections.Generic.List[string]
		
		# Set dissam mode
		if ($x32) {
			$cs_mode = "CS_MODE_32"
		} else {
			$cs_mode = "CS_MODE_64"
		}
		
		while ($ETrace.Count -lt $InstructionCount) {
			# Maintain instruction count
			$Count = 0
			
			# Get valid instruction
			while ($(Get-CapstoneDisassembly -Architecture CS_ARCH_X86 -Mode $cs_mode -Address $($MemEP + $ImageBase) -Bytes $($FileBytes[($Address)..($Address+$Count)]) -Detailed) -like "*Fail*") {
				$Count += 1
			} 
			
			# Store result in $Instruction for analysis and add to $ETrace
			[Array]$Instruction = $(Get-CapstoneDisassembly -Architecture CS_ARCH_X86 -Mode $cs_mode -Address $($MemEP + $ImageBase) -Bytes $($FileBytes[($Address)..($Address+$Count)]) -Detailed)
			$ETrace += $Instruction |Select Size,Address,Mnemonic,Operands,Bytes,RegRead,RegWrite
	
			# Branching based on the instruction
			#-------------
			if ($Instruction[0].Mnemonic -eq "jmp" -Or $Instruction[0].Mnemonic -eq "call") {
				if ($Instruction[0].Operands -like "*dword*") {
					# We are skipping indirect call/jmp's. Almost all of these
					# reference PE module addresses which we can't disassemble.
					# A tiny amount can reference a location we have access
					# too but we can't reliably tell because they may be patched
					# at runtime.
					#
					# For testing purposes, the following regex can be used to
					# extract the offset (try/catch to detect if it is an integer).
					#-------------
					# IEX([regex]"\[([^\[]*)\]").Match($Instruction[0].Operands).Groups[1].Value
					#-------------
					$Address = $Address + $Instruction[0].Size
					$MemEP = $MemEP + $Instruction[0].Size
					
					# Add to $CallTrace
					$HashTable = @{
						Address = $($Instruction[0].Address)
						Mnemonic = $($Instruction[0].Mnemonic)
						Taken = "No"
						Reason = "Indirect $($Instruction[0].Mnemonic)"
					}
					$Object = New-Object PSObject -Property $HashTable |Select Address,Mnemonic,Taken,Reason
					$CallTrace += $Object
				} else {
					# This fails if non-int, eg "call eax"
					# we can't get the value for this so -> catch
					try {
						$Offset = $Address + $([UInt64]$Instruction[0].Operands - [UInt64]$Instruction[0].Address)
						if ($Offset -le $FileBytes.Count) {
							#echo "$($Instruction[0].Mnemonic) taken"
							if ($Instruction[0].Mnemonic -eq "jmp") {
								$Address = $Address + $([UInt64]$Instruction[0].Operands - [UInt64]$Instruction[0].Address)
								$MemEP = $MemEP + $([UInt64]$Instruction[0].Operands - [UInt64]$Instruction[0].Address)
								
								# Add to $CallTrace
								$HashTable = @{
									Address = $($Instruction[0].Address)
									Mnemonic = $($Instruction[0].Mnemonic)
									Taken = "Yes"
									Reason = "Relative offset jmp"
								}
								$Object = New-Object PSObject -Property $HashTable |Select Address,Mnemonic,Taken,Reason
								$CallTrace += $Object
							} else {
								# Store return addresses in FIFO list
								$RetFIFO.Insert(0,$($Address + $Instruction[0].Size))
								$RetFIFO.Insert(1,$($MemEP + $Instruction[0].Size))
								
								# follow the call instruction
								$Address = $Address + $([UInt64]$Instruction[0].Operands - [UInt64]$Instruction[0].Address)
								$MemEP = $MemEP + $([UInt64]$Instruction[0].Operands - [UInt64]$Instruction[0].Address)
								
								# Add to $CallTrace
								$HashTable = @{
									Address = $($Instruction[0].Address)
									Mnemonic = $($Instruction[0].Mnemonic)
									Taken = "Yes"
									Reason = "Relative offset call"
								}
								$Object = New-Object PSObject -Property $HashTable |Select Address,Mnemonic,Taken,Reason
								$CallTrace += $Object
							}
						} else {
							# Address out of PE range so continue dissasm
							$Address = $Address + $Instruction[0].Size
							$MemEP = $MemEP + $Instruction[0].Size
							
							# Add to $CallTrace
							$HashTable = @{
								Address = $($Instruction[0].Address)
								Mnemonic = $($Instruction[0].Mnemonic)
								Taken = "No"
								Reason = "Offset outside PE range"
							}
							$Object = New-Object PSObject -Property $HashTable |Select Address,Mnemonic,Taken,Reason
							$CallTrace += $Object
						}
					} catch {
						# We can't get value here so continue dissam
						$Address = $Address + $Instruction[0].Size
						$MemEP = $MemEP + $Instruction[0].Size
						
						# Add to $CallTrace
						$HashTable = @{
							Address = $($Instruction[0].Address)
							Mnemonic = $($Instruction[0].Mnemonic)
							Taken = "No"
							Reason = "$($Instruction[0].Mnemonic) references a register"
						}
						$Object = New-Object PSObject -Property $HashTable |Select Address,Mnemonic,Taken,Reason
						$CallTrace += $Object
					}
				}
			} elseif ($Instruction[0].Mnemonic -eq "ret") {
				if ($RetFIFO[0]) {
					# Get return addresses from FIFO list and clear them
					$Address = [UInt64]$RetFIFO[0]
					$MemEP = [UInt64]$RetFIFO[1]
					$RetFIFO.RemoveRange(0,2)
					
					# Add to $CallTrace
					$HashTable = @{
						Address = $($Instruction[0].Address)
						Mnemonic = $($Instruction[0].Mnemonic)
						Taken = "Yes"
						Reason = "Return from function call"
					}
					$Object = New-Object PSObject -Property $HashTable |Select Address,Mnemonic,Taken,Reason
					$CallTrace += $Object
				} else {
					# If no ret values, end of program?
					break
				}
			} else {
				$Address = $Address + $Instruction[0].Size
				$MemEP = $MemEP + $Instruction[0].Size
			}
		}
		$Script:CallTrace = $CallTrace
		$Script:ETrace = $ETrace
	}
	
	# Read/alloc file bytes
	$FileBytes = [System.IO.File]::ReadAllBytes($Path)
	[IntPtr]$HModule = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($FileBytes.Length)
	[System.Runtime.InteropServices.Marshal]::Copy($FileBytes, 0, $HModule, $FileBytes.Length)
	
	# Get $InMemoryEntryPoint, $ImageBase, $SectionArray and $x32/!$x32
	Return-PeInfo $HModule
	
	# EntryPoint to file offset
	$FileOffset = Convert-RVAToFileOffset $InMemoryEntryPoint $SectionArray
	
	# Trace execution flow
	Follow-ASM $FileOffset $InMemoryEntryPoint $ImageBase
	
	# Slight spacing nightmare below, dirty fix..
	echo "`n[?] Call table:`n"
	($CallTrace |ft -Autosize |Out-String).trim()
	
	echo "`n[?] Instruction trace:`n"
	($ETrace |ft -Autosize |Out-String).trim()
	
	echo ""

	# Free buffer
	[Runtime.InteropServices.Marshal]::FreeHGlobal($HModule)
}