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
	C:\PS> $SystemProcHandles = Get-Handles -ProcID 4
	C:\PS> $Key = $SystemProcHandles |Where-Object {$_.ObjectType -eq "Key"}
	C:\PS> $Key |ft

	ObjectType AccessMask PID Handle HandleFlags KernelPointer
	---------- ---------- --- ------ ----------- -------------
	Key        0x00000000   4 0x004C NONE        0xFFFFC9076FC29BC0
	Key        0x00020000   4 0x0054 NONE        0xFFFFC9076FCDA7F0
	Key        0x000F0000   4 0x0058 NONE        0xFFFFC9076FC39CE0
	Key        0x00000000   4 0x0090 NONE        0xFFFFC907700A6B40
	Key        0x00000000   4 0x0098 NONE        0xFFFFC90770029F70
	Key        0x00020000   4 0x00A0 NONE        0xFFFFC9076FC9C1A0
	[...Snip...]
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
	
	public static class GetHandles
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
		Return
	}

	# Flag switches (0 = NONE?)
	$FlagSwitches = @{
		0 = 'NONE'
		1 = 'PROTECT_FROM_CLOSE'
		2 = 'INHERIT'
	}
	
	$OSVersion = [Version](Get-WmiObject Win32_OperatingSystem).Version
	$OSMajorMinor = "$($OSVersion.Major).$($OSVersion.Minor)"
	switch ($OSMajorMinor)
	{
		'10.0'
		{
			# Win 10 v1709 (RS3)
			if ($OSVersion.Build -ge 16299) {
				$TypeSwitches = @{
					0x25 = 'TmTm'; 0x19 = 'Desktop'; 0x7 = 'Process'; 0x2e = 'EnergyTracker'; 0x2c = 'RegistryTransaction';
					0xf = 'DebugObject'; 0x41 = 'VRegConfigurationContext'; 0x35 = 'DmaDomain'; 0x1d = 'TpWorkerFactory';
					0x1e = 'Adapter'; 0x5 = 'Token'; 0x3a = 'DxgkSharedResource'; 0xd = 'PsSiloContextPaged';
					0x39 = 'NdisCmState'; 0xc = 'ActivityReference'; 0x36 = 'PcwObject'; 0x30 = 'WmiGuid'; 0x34 = 'DmaAdapter';
					0x31 = 'EtwRegistration'; 0x40 = 'DxgkSharedBundleObject'; 0x2a = 'Session'; 0x1b = 'RawInputManager';
					0x14 = 'Timer'; 0x11 = 'Mutant'; 0x15 = 'IRTimer'; 0x3e = 'DxgkCurrentDxgProcessObject';
					0x22 = 'IoCompletion'; 0x3f = 'DxgkSharedProtectedSessionObject'; 0x3b = 'DxgkSharedSyncObject';
					0x18 = 'WindowStation'; 0x16 = 'Profile'; 0x24 = 'File'; 0x9 = 'Partition'; 0x13 = 'Semaphore';
					0xe = 'PsSiloContextNonPaged'; 0x33 = 'EtwConsumer'; 0x1a = 'Composition'; 0x32 = 'EtwSessionDemuxEntry';
					0x1c = 'CoreMessaging'; 0x26 = 'TmTx'; 0x4 = 'SymbolicLink'; 0x37 = 'FilterConnectionPort'; 0x2b = 'Key';
					0x17 = 'KeyedEvent'; 0x12 = 'Callback'; 0x23 = 'WaitCompletionPacket'; 0xa = 'UserApcReserve'; 0x6 = 'Job';
					0x3d = 'DxgkDisplayManagerObject'; 0x3c = 'DxgkSharedSwapChainObject'; 0x1f = 'Controller';
					0xb = 'IoCompletionReserve'; 0x20 = 'Device'; 0x3 = 'Directory'; 0x29 = 'Section'; 0x28 = 'TmEn';
					0x8 = 'Thread'; 0x2 = 'Type'; 0x38 = 'FilterCommunicationPort'; 0x2f = 'PowerRequest'; 0x27 = 'TmRm';
					0x10 = 'Event'; 0x2d = 'ALPC Port'; 0x21 = 'Driver';
				}
			}
			
			# Win 10 v1703 (RS2)
			if ($OSVersion.Build -ge 15063 -And $OSVersion.Build -lt 16299) {
				$TypeSwitches = @{
					0x24 = 'TmTm'; 0x18 = 'Desktop'; 0x7 = 'Process'; 0x2c = 'RegistryTransaction'; 0xe = 'DebugObject';
					0x3d = 'VRegConfigurationContext'; 0x34 = 'DmaDomain'; 0x1c = 'TpWorkerFactory'; 0x1d = 'Adapter';
					0x5 = 'Token'; 0x39 = 'DxgkSharedResource'; 0xc = 'PsSiloContextPaged'; 0x38 = 'NdisCmState';
					0xb = 'ActivityReference'; 0x35 = 'PcwObject'; 0x2f = 'WmiGuid'; 0x33 = 'DmaAdapter';
					0x30 = 'EtwRegistration'; 0x29 = 'Session'; 0x1a = 'RawInputManager'; 0x13 = 'Timer'; 0x10 = 'Mutant';
					0x14 = 'IRTimer'; 0x3c = 'DxgkCurrentDxgProcessObject'; 0x21 = 'IoCompletion';
					0x3a = 'DxgkSharedSyncObject'; 0x17 = 'WindowStation'; 0x15 = 'Profile'; 0x23 = 'File';
					0x2a = 'Partition'; 0x12 = 'Semaphore'; 0xd = 'PsSiloContextNonPaged'; 0x32 = 'EtwConsumer';
					0x19 = 'Composition'; 0x31 = 'EtwSessionDemuxEntry'; 0x1b = 'CoreMessaging'; 0x25 = 'TmTx';
					0x4 = 'SymbolicLink'; 0x36 = 'FilterConnectionPort'; 0x2b = 'Key'; 0x16 = 'KeyedEvent';
					0x11 = 'Callback'; 0x22 = 'WaitCompletionPacket'; 0x9 = 'UserApcReserve'; 0x6 = 'Job';
					0x3b = 'DxgkSharedSwapChainObject'; 0x1e = 'Controller'; 0xa = 'IoCompletionReserve'; 0x1f = 'Device';
					0x3 = 'Directory'; 0x28 = 'Section'; 0x27 = 'TmEn'; 0x8 = 'Thread'; 0x2 = 'Type';
					0x37 = 'FilterCommunicationPort'; 0x2e = 'PowerRequest'; 0x26 = 'TmRm'; 0xf = 'Event';
					0x2d = 'ALPC Port'; 0x20 = 'Driver';
				}
			}
			
			# Win 10 v1607 (RS1)
			if ($OSVersion.Build -ge 14393 -And $OSVersion.Build -lt 15063) {
				$TypeSwitches = @{
					0x23 = 'TmTm'; 0x17 = 'Desktop'; 0x7 = 'Process'; 0x2b = 'RegistryTransaction'; 0xd = 'DebugObject';
					0x3a = 'VRegConfigurationContext'; 0x32 = 'DmaDomain'; 0x1b = 'TpWorkerFactory'; 0x1c = 'Adapter';
					0x5 = 'Token'; 0x37 = 'DxgkSharedResource'; 0xb = 'PsSiloContextPaged'; 0x36 = 'NdisCmState';
					0x33 = 'PcwObject'; 0x2e = 'WmiGuid'; 0x31 = 'DmaAdapter'; 0x2f = 'EtwRegistration';
					0x28 = 'Session'; 0x19 = 'RawInputManager'; 0x12 = 'Timer'; 0xf = 'Mutant'; 0x13 = 'IRTimer';
					0x20 = 'IoCompletion'; 0x38 = 'DxgkSharedSyncObject'; 0x16 = 'WindowStation'; 0x14 = 'Profile';
					0x22 = 'File'; 0x3b = 'VirtualKey'; 0x29 = 'Partition'; 0x11 = 'Semaphore'; 0xc = 'PsSiloContextNonPaged';
					0x30 = 'EtwConsumer'; 0x18 = 'Composition'; 0x1a = 'CoreMessaging'; 0x24 = 'TmTx'; 0x4 = 'SymbolicLink';
					0x34 = 'FilterConnectionPort'; 0x2a = 'Key'; 0x15 = 'KeyedEvent'; 0x10 = 'Callback';
					0x21 = 'WaitCompletionPacket'; 0x9 = 'UserApcReserve'; 0x6 = 'Job'; 0x39 = 'DxgkSharedSwapChainObject';
					0x1d = 'Controller'; 0xa = 'IoCompletionReserve'; 0x1e = 'Device'; 0x3 = 'Directory'; 0x27 = 'Section';
					0x26 = 'TmEn'; 0x8 = 'Thread'; 0x2 = 'Type'; 0x35 = 'FilterCommunicationPort'; 0x2d = 'PowerRequest';
					0x25 = 'TmRm'; 0xe = 'Event'; 0x2c = 'ALPC Port'; 0x1f = 'Driver';
				}
			}
			
			# Win 10 v1511
			if ($OSVersion.Build -lt 14393) {
				$TypeSwitches = @{
					0x02 = 'Type'; 0x03 = 'Directory'; 0x04 = 'SymbolicLink'; 0x05 = 'Token'; 0x06 = 'Job';
					0x07 = 'Process'; 0x08 = 'Thread'; 0x09 = 'UserApcReserve'; 0x0A = 'IoCompletionReserve';
					0x0B = 'DebugObject'; 0x0C = 'Event'; 0x0D = 'Mutant'; 0x0E = 'Callback'; 0x0F = 'Semaphore';
					0x10 = 'Timer'; 0x11 = 'IRTimer'; 0x12 = 'Profile'; 0x13 = 'KeyedEvent'; 0x14 = 'WindowStation';
					0x15 = 'Desktop'; 0x16 = 'Composition'; 0x17 = 'RawInputManager'; 0x18 = 'TpWorkerFactory';
					0x19 = 'Adapter'; 0x1A = 'Controller'; 0x1B = 'Device'; 0x1C = 'Driver'; 0x1D = 'IoCompletion';
					0x1E = 'WaitCompletionPacket'; 0x1F = 'File'; 0x20 = 'TmTm'; 0x21 = 'TmTx'; 0x22 = 'TmRm';
					0x23 = 'TmEn'; 0x24 = 'Section'; 0x25 = 'Session'; 0x26 = 'Partition'; 0x27 = 'Key';
					0x28 = 'ALPC Port'; 0x29 = 'PowerRequest'; 0x2A = 'WmiGuid'; 0x2B = 'EtwRegistration';
					0x2C = 'EtwConsumer'; 0x2D = 'DmaAdapter'; 0x2E = 'DmaDomain'; 0x2F = 'PcwObject';
					0x30 = 'FilterConnectionPort'; 0x31 = 'FilterCommunicationPort'; 0x32 = 'NetworkNamespace';
					0x33 = 'DxgkSharedResource'; 0x34 = 'DxgkSharedSyncObject'; 0x35 = 'DxgkSharedSwapChainObject';
				}
			}
		}
		
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

	[int]$BuffPtr_Size = 0
	while ($true) {
		[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
		$SystemInformationLength = New-Object Int
	
		$CallResult = [GetHandles]::NtQuerySystemInformation(16, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)
		
		# STATUS_INFO_LENGTH_MISMATCH
		if ($CallResult -eq 0xC0000004) {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
			[int]$BuffPtr_Size = [System.Math]::Max($BuffPtr_Size,$SystemInformationLength)
		}
		# STATUS_SUCCESS
		elseif ($CallResult -eq 0x00000000) {
			break
		}
		# Probably: 0xC0000005 -> STATUS_ACCESS_VIOLATION
		else {
			[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
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
	
	$SystemHandleArray = @()
	for ($i=0; $i -lt $HandleCount; $i++){
		# PtrToStructure only objects we are targeting, this is expensive computation
		if ([System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset) -eq $ProcID) {
			$SystemPointer = New-Object System.Intptr -ArgumentList $BuffOffset
			$Cast = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SYSTEM_HANDLE_INFORMATION)
			
			$HashTable = @{
				PID = $Cast.ProcessID
				ObjectType = if (!$($TypeSwitches[[int]$Cast.ObjectTypeNumber])) { "0x$('{0:X2}' -f [int]$Cast.ObjectTypeNumber)" } else { $TypeSwitches[[int]$Cast.ObjectTypeNumber] }
				HandleFlags = $FlagSwitches[[int]$Cast.Flags]
				Handle = "0x$('{0:X4}' -f [int]$Cast.HandleValue)"
				KernelPointer = if ([System.IntPtr]::Size -eq 4) { "0x$('{0:X}' -f $Cast.Object_Pointer.ToInt32())" } else { "0x$('{0:X}' -f $Cast.Object_Pointer.ToInt64())" }
				AccessMask = "0x$('{0:X8}' -f $($Cast.GrantedAccess -band 0xFFFF0000))"
			}
			
			$Object = New-Object PSObject -Property $HashTable
			$SystemHandleArray += $Object
			
		}

		$BuffOffset = $BuffOffset + $SYSTEM_HANDLE_INFORMATION_Size
	}
	
	if ($($SystemHandleArray.count) -eq 0) {
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
		Return
	}
	
	# Set column order and auto size
	$SystemHandleArray
	
	# Free SYSTEM_HANDLE_INFORMATION array
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
}