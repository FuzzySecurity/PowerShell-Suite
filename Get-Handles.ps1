function Get-Handles {
<#
.SYNOPSIS
	Use NtQuerySystemInformation::SystemHandleInformation to get a list of
	open handles in the specified process, works on x32/x64.

	Notes:

	* For more robust coding I would recomend using @mattifestation's
	  Get-NtSystemInformation.ps1 part of PowerShellArsenal.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	C:\PS> Get-Handles -ProcID 1234

#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[int]$ProcID
	)
	
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct SYSTEM_HANDLE_INFORMATION
	{
		public UInt32 ProcessID;
		public Byte ObjectTypeNumber;
		public Byte Flags;
		public UInt16 HandleValue;
		public IntPtr Object_Pointer;
		public UInt32 GrantedAccess;
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
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

	# Make sure the PID exists
	if (!$(get-process -Id $ProcID -ErrorAction SilentlyContinue)) {
		echo "`n[!] The specified PID doesn't exist, exiting..`n"
		Return
	} else {
		echo "`n[>] PID $ProcID --> $((Get-Process -Id $ProcID).ProcessName)"
	}

	# Flag switches (0 = NONE?)
	$FlagSwitches = @{
		0 = 'NONE'
		1 = 'PROTECT_FROM_CLOSE'
		2 = 'INHERIT'
	}
	
	# Taken from @mattifestation --> Get-NtSystemInformation.ps1
	# https://github.com/mattifestation/PowerShellArsenal/blob/master/WindowsInternals/Get-NtSystemInformation.ps1
	$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
	$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
	switch ($OSMajorMinor)
	{
		'6.2' # Windows 8 and Windows Server 2012
		{
			$TypeSwitches = @{
				0x02 = 'Type'; 0x03 = 'Directory'; 0x04 = 'SymbolicLink'; 0x05 = 'Token'; 0x06 = 'Job';
				0x07 = 'Process'; 0x08 = 'Thread'; 0x09 = 'UserApcReserve'; 0x0A = 'IoCompletionReserve';
				0x0B = 'DebugObject'; 0x0C = 'Event'; 0x0D = 'EventPair'; 0x0E = 'Mutant'; 0x0F = 'Callback';
				0x10 = 'Semaphore'; 0x11 = 'Timer'; 0x12 = 'IRTimer'; 0x13 = 'Profile'; 0x14 = 'KeyedEvent';
				0x15 = 'WindowStation'; 0x16 = 'Desktop'; 0x17 = 'CompositionSurface'; 0x18 = 'TpWorkerFactory';
				0x19 = 'Adapter'; 0x1A = 'Controller'; 0x1B = 'Device'; 0x1C = 'Driver'; 0x1D = 'IoCompletion';
				0x1E = 'WaitCompletionPacket'; 0x1F = 'File'; 0x20 = 'TmTm'; 0x21 = 'TmTx'; 0x22 = 'TmRm';
				0x23 = 'TmEn'; 0x24 = 'Section'; 0x25 = 'Session'; 0x26 = 'Key'; 0x27 = 'ALPC Port';
				0x28 = 'PowerRequest'; 0x29 = 'WmiGuid'; 0x2A = 'EtwRegistration'; 0x2B = 'EtwConsumer';
				0x2C = 'FilterConnectionPort'; 0x2D = 'FilterCommunicationPort'; 0x2E = 'PcwObject';
				0x2F = 'DxgkSharedResource'; 0x30 = 'DxgkSharedSyncObject';
			}
		}
	
		'6.1' # Windows 7 and Window Server 2008 R2
		{
			$TypeSwitches = @{
				0x02 = 'Type'; 0x03 = 'Directory'; 0x04 = 'SymbolicLink'; 0x05 = 'Token'; 0x06 = 'Job';
				0x07 = 'Process'; 0x08 = 'Thread'; 0x09 = 'UserApcReserve'; 0x0a = 'IoCompletionReserve';
				0x0b = 'DebugObject'; 0x0c = 'Event'; 0x0d = 'EventPair'; 0x0e = 'Mutant'; 0x0f = 'Callback';
				0x10 = 'Semaphore'; 0x11 = 'Timer'; 0x12 = 'Profile'; 0x13 = 'KeyedEvent'; 0x14 = 'WindowStation';
				0x15 = 'Desktop'; 0x16 = 'TpWorkerFactory'; 0x17 = 'Adapter'; 0x18 = 'Controller';
				0x19 = 'Device'; 0x1a = 'Driver'; 0x1b = 'IoCompletion'; 0x1c = 'File'; 0x1d = 'TmTm';
				0x1e = 'TmTx'; 0x1f = 'TmRm'; 0x20 = 'TmEn'; 0x21 = 'Section'; 0x22 = 'Session'; 0x23 = 'Key';
				0x24 = 'ALPC Port'; 0x25 = 'PowerRequest'; 0x26 = 'WmiGuid'; 0x27 = 'EtwRegistration';
				0x28 = 'EtwConsumer'; 0x29 = 'FilterConnectionPort'; 0x2a = 'FilterCommunicationPort';
				0x2b = 'PcwObject';
			}
		}
	
		'6.0' # Windows Vista and Windows Server 2008
		{
			$TypeSwitches = @{
				0x01 = 'Type'; 0x02 = 'Directory'; 0x03 = 'SymbolicLink'; 0x04 = 'Token'; 0x05 = 'Job';
				0x06 = 'Process'; 0x07 = 'Thread'; 0x08 = 'DebugObject'; 0x09 = 'Event'; 0x0a = 'EventPair';
				0x0b = 'Mutant'; 0x0c = 'Callback'; 0x0d = 'Semaphore'; 0x0e = 'Timer'; 0x0f = 'Profile';
				0x10 = 'KeyedEvent'; 0x11 = 'WindowStation'; 0x12 = 'Desktop'; 0x13 = 'TpWorkerFactory';
				0x14 = 'Adapter'; 0x15 = 'Controller'; 0x16 = 'Device'; 0x17 = 'Driver'; 0x18 = 'IoCompletion';
				0x19 = 'File'; 0x1a = 'TmTm'; 0x1b = 'TmTx'; 0x1c = 'TmRm'; 0x1d = 'TmEn'; 0x1e = 'Section';
				0x1f = 'Session'; 0x20 = 'Key'; 0x21 = 'ALPC Port'; 0x22 = 'WmiGuid'; 0x23 = 'EtwRegistration';
				0x24 = 'FilterConnectionPort'; 0x25 = 'FilterCommunicationPort';
			}
		}
	}
	
	echo "[+] Calling NtQuerySystemInformation::SystemHandleInformation"
	[int]$BuffPtr_Size = 0
	while ($true) {
		[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
		$SystemInformationLength = New-Object Int
	
		$CallResult = [Ntdll]::NtQuerySystemInformation(16, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)
		
		# STATUS_INFO_LENGTH_MISMATCH
		if ($CallResult -eq 0xC0000004) {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
			[int]$BuffPtr_Size = [System.Math]::Max($BuffPtr_Size,$SystemInformationLength)
		}
		# STATUS_SUCCESS
		elseif ($CallResult -eq 0x00000000) {
			echo "[?] Success, allocated $BuffPtr_Size byte result buffer`n"
			break
		}
		# Probably: 0xC0000005 -> STATUS_ACCESS_VIOLATION
		else {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
			echo "[!] Error, NTSTATUS Value: $('{0:X}' -f ($CallResult))`n"
			return
		}
	}
	
	$SYSTEM_HANDLE_INFORMATION = New-Object SYSTEM_HANDLE_INFORMATION
	$SYSTEM_HANDLE_INFORMATION = $SYSTEM_HANDLE_INFORMATION.GetType()
	if ([System.IntPtr]::Size -eq 4) {
		$SYSTEM_HANDLE_INFORMATION_Size = 16 # This makes sense!
	} else {
		$SYSTEM_HANDLE_INFORMATION_Size = 24 # This doesn't make sense, should be 20 on x64 but that doesn't work.
                                             # Ask no questions, hear no lies!
	}
	
	$BuffOffset = $BuffPtr.ToInt64()
	$HandleCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)
	$BuffOffset = $BuffOffset + [System.IntPtr]::Size
	echo "[>] Result buffer contains $HandleCount SystemHandleInformation objects"
	
	$SystemHandleArray = @()
	for ($i=0; $i -lt $HandleCount; $i++){
		# PtrToStructure only objects we are targeting, this is expensive computation
		if ([System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset) -eq $ProcID) {
			$SystemPointer = New-Object System.Intptr -ArgumentList $BuffOffset
			$Cast = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SYSTEM_HANDLE_INFORMATION)
			
			$HashTable = @{
				PID = $Cast.ProcessID
				ObjectType = $TypeSwitches[[int]$Cast.ObjectTypeNumber]
				HandleFlags = $FlagSwitches[[int]$Cast.Flags]
				Handle = "0x$('{0:X4}' -f [int]$Cast.HandleValue)"
				KernelPointer = if ([System.IntPtr]::Size -eq 4) {
									"0x$('{0:X}' -f $Cast.Object_Pointer.ToInt32())"
								} else {
									"0x$('{0:X}' -f $Cast.Object_Pointer.ToInt64())"
								}
				AccessMask = "0x$('{0:X8}' -f $($Cast.GrantedAccess -band 0xFFFF0000))"
			}
			
			$Object = New-Object PSObject -Property $HashTable
			$SystemHandleArray += $Object
		}
		$BuffOffset = $BuffOffset + $SYSTEM_HANDLE_INFORMATION_Size
	}
	
	echo "[>] PID $ProcID has $($SystemHandleArray.count) handle objects"
	if ($($SystemHandleArray.count) -eq 0) {
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
		echo "[!] No process handles found, exiting..`n"
		Return
	}
	
	# Set column order and auto size
	$SystemHandleArray |Select-Object PID,ObjectType,HandleFlags,Handle,KernelPointer,AccessMask |Format-Table -AutoSize
	
	# Free SYSTEM_HANDLE_INFORMATION array
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
}