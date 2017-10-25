function Get-SystemProcessInformation {
<#
.SYNOPSIS
	Use NtQuerySystemInformation::SystemProcessInformation to get a detailed
	list of processes and process properties. On close inspection you will
	find that many process monitors such as Sysinternals Process Explorer or
	Process Hacker use this information class (in addition to
	SystemPerformanceInformation, SystemProcessorPerformanceInformation and
	SystemProcessorCycleTimeInformation).

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER ProcID
	PID of the target process.

.PARAMETER ProcName
	Wild card search for the process name

.EXAMPLE
	# Return full process listing
	C:\PS> Get-SystemProcessInformation

.EXAMPLE
	# Return only specific PID
	C:\PS> Get-SystemProcessInformation -ProcID 1336
	
	PID                        : 1336
	InheritedFromPID           : 1020
	ImageName                  : svchost.exe
	Priority                   : 8
	CreateTime                 : 0d:9h:8m:47s
	UserCPU                    : 0d:0h:0m:0s
	KernelCPU                  : 0d:0h:0m:0s
	ThreadCount                : 12
	HandleCount                : 387
	PageFaults                 : 7655
	SessionId                  : 0
	PageDirectoryBase          : 3821568
	PeakVirtualSize            : 2097249.796875 MB
	VirtualSize                : 2097240.796875 MB
	PeakWorkingSetSize         : 11.65625 MB
	WorkingSetSize             : 6.2109375 MB
	QuotaPeakPagedPoolUsage    : 0.175910949707031 MB
	QuotaPagedPoolUsage        : 0.167121887207031 MB
	QuotaPeakNonPagedPoolUsage : 0.0151519775390625 MB
	QuotaNonPagedPoolUsage     : 0.0137710571289063 MB
	PagefileUsage              : 3.64453125 MB
	PeakPagefileUsage          : 4.14453125 MB
	PrivatePageCount           : 3.64453125 MB
	ReadOperationCount         : 0
	WriteOperationCount        : 0
	OtherOperationCount        : 223
	ReadTransferCount          : 0
	WriteTransferCount         : 0
	OtherTransferCount         : 25010

.EXAMPLE
	# Possibly returns multiple processes
	# eg: notepad.exe & notepad++.exe
	C:\PS> Get-SystemProcessInformation -ProcName note
#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $False)]
		[int]$ProcID,
		[Parameter(Mandatory = $False)]
		[string]$ProcName
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
	public struct SystemProcessInformation
	{
		public int NextEntryOffset; 
		public uint NumberOfThreads;
		public long SpareLi1; 
		public long SpareLi2; 
		public long SpareLi3;
		public long CreateTime; 
		public long UserTime;
		public long KernelTime;
		public UNICODE_STRING ImageName;
		public int BasePriority;
		public IntPtr UniqueProcessId; 
		public IntPtr InheritedFromUniqueProcessId;
		public uint HandleCount;
		public uint SessionId;
		public IntPtr PageDirectoryBase; 
		public IntPtr PeakVirtualSize;
		public IntPtr VirtualSize; 
		public uint   PageFaultCount; 
		public IntPtr PeakWorkingSetSize; 
		public IntPtr WorkingSetSize;
		public IntPtr QuotaPeakPagedPoolUsage;
		public IntPtr QuotaPagedPoolUsage;
		public IntPtr QuotaPeakNonPagedPoolUsage; 
		public IntPtr QuotaNonPagedPoolUsage;
		public IntPtr PagefileUsage; 
		public IntPtr PeakPagefileUsage; 
		public IntPtr PrivatePageCount;
		public long ReadOperationCount;
		public long WriteOperationCount;
		public long OtherOperationCount;
		public long ReadTransferCount; 
		public long WriteTransferCount;
		public long OtherTransferCount; 
	} 
	
	public static class SystemProcInfo
	{
		[DllImport("ntdll.dll")]
		public static extern int NtQuerySystemInformation(
			int SystemInformationClass,
			IntPtr SystemInformation,
			int SystemInformationLength,
			ref int ReturnLength);
	}
"@
	
	[int]$BuffPtr_Size = 0
	while ($true) {
		[IntPtr]$BuffPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BuffPtr_Size)
		$SystemInformationLength = New-Object Int
	
		# SystemProcessInformation Class = 5
		$CallResult = [SystemProcInfo]::NtQuerySystemInformation(5, $BuffPtr, $BuffPtr_Size, [ref]$SystemInformationLength)
		
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
	
	# Create in-memory struct
	$SystemProcessInformation = New-Object SystemProcessInformation
	$SystemProcessInformation = $SystemProcessInformation.GetType()
	$BuffOffset = $BuffPtr.ToInt64()
	
	$SystemModuleArray = @()
	while ($true) {
		$SystemPointer = New-Object System.Intptr -ArgumentList $($BuffOffset)
		$Struct = [system.runtime.interopservices.marshal]::PtrToStructure($SystemPointer,[type]$SystemProcessInformation)
	
		$HashTable = @{
			PID = $Struct.UniqueProcessId
			InheritedFromPID = $Struct.InheritedFromUniqueProcessId
			ImageName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Struct.ImageName.Buffer)
			Priority = $Struct.BasePriority
			CreateTime = "$(([datetime]::FromBinary($Struct.CreateTime)).TimeOfDay.Days)d:$(([datetime]::FromBinary($Struct.CreateTime)).TimeOfDay.Hours)h:$(([datetime]::FromBinary($Struct.CreateTime)).TimeOfDay.Minutes)m:$(([datetime]::FromBinary($Struct.CreateTime)).TimeOfDay.Seconds)s"
			UserCPU = "$(([datetime]::FromBinary($Struct.UserTime)).TimeOfDay.Days)d:$(([datetime]::FromBinary($Struct.UserTime)).TimeOfDay.Hours)h:$(([datetime]::FromBinary($Struct.UserTime)).TimeOfDay.Minutes)m:$(([datetime]::FromBinary($Struct.UserTime)).TimeOfDay.Seconds)s"
			KernelCPU = "$(([datetime]::FromBinary($Struct.KernelTime)).TimeOfDay.Days)d:$(([datetime]::FromBinary($Struct.KernelTime)).TimeOfDay.Hours)h:$(([datetime]::FromBinary($Struct.KernelTime)).TimeOfDay.Minutes)m:$(([datetime]::FromBinary($Struct.KernelTime)).TimeOfDay.Seconds)s"
			ThreadCount = $Struct.NumberOfThreads
			HandleCount = $Struct.HandleCount
			PageFaults = $Struct.PageFaultCount
			SessionId = $Struct.SessionId
			PageDirectoryBase = $Struct.PageDirectoryBase
			PeakVirtualSize = "$($Struct.PeakVirtualSize.ToInt64()/[math]::pow(1024,2)) MB"
			VirtualSize = "$($Struct.VirtualSize.ToInt64()/[math]::pow(1024,2)) MB"
			PeakWorkingSetSize = "$($Struct.PeakWorkingSetSize.ToInt64()/[math]::pow(1024,2)) MB"
			WorkingSetSize = "$($Struct.WorkingSetSize.ToInt64()/[math]::pow(1024,2)) MB"
			QuotaPeakPagedPoolUsage = "$($Struct.QuotaPeakPagedPoolUsage.ToInt64()/[math]::pow(1024,2)) MB"
			QuotaPagedPoolUsage = "$($Struct.QuotaPagedPoolUsage.ToInt64()/[math]::pow(1024,2)) MB"
			QuotaPeakNonPagedPoolUsage = "$($Struct.QuotaPeakNonPagedPoolUsage.ToInt64()/[math]::pow(1024,2)) MB"
			QuotaNonPagedPoolUsage = "$($Struct.QuotaNonPagedPoolUsage.ToInt64()/[math]::pow(1024,2)) MB"
			PagefileUsage = "$($Struct.PagefileUsage.ToInt64()/[math]::pow(1024,2)) MB"
			PeakPagefileUsage = "$($Struct.PeakPagefileUsage.ToInt64()/[math]::pow(1024,2)) MB"
			PrivatePageCount = "$($Struct.PrivatePageCount.ToInt64()/[math]::pow(1024,2)) MB"
			ReadOperationCount = $Struct.ReadOperationCount
			WriteOperationCount = $Struct.WriteOperationCount
			OtherOperationCount = $Struct.OtherOperationCount
			ReadTransferCount = $Struct.ReadTransferCount
			WriteTransferCount = $Struct.WriteTransferCount
			OtherTransferCount = $Struct.OtherTransferCount
		}
		$Object = New-Object PSObject -Property $HashTable
		$SystemModuleArray += $Object
	
		# Check if we reached the end of the list
		if ($([System.Runtime.InteropServices.Marshal]::ReadInt32($BuffOffset)) -eq 0) {
			Break
		} else {
			$BuffOffset = $BuffOffset + $Struct.NextEntryOffset
		}
	}
	
	# Free allocated SystemModuleInformation array
	[System.Runtime.InteropServices.Marshal]::FreeHGlobal($BuffPtr)
	
	# We want this object in a specific order
	$ResultObject = $SystemModuleArray |Select PID,InheritedFromPID,ImageName,Priority,CreateTime,UserCPU,KernelCPU,ThreadCount,HandleCount,PageFaults,SessionId,PageDirectoryBase,PeakVirtualSize,VirtualSize,PeakWorkingSetSize,WorkingSetSize,QuotaPeakPagedPoolUsage,QuotaPagedPoolUsage,QuotaPeakNonPagedPoolUsage,QuotaNonPagedPoolUsage,PagefileUsage,PeakPagefileUsage,PrivatePageCount,ReadOperationCount,WriteOperationCount,OtherOperationCount,ReadTransferCount,WriteTransferCount,OtherTransferCount

	# Display output
	if (!$ProcID -And !$ProcName) {
		$ResultObject # Just print
		Return
	}
	if ($ProcID) {
		$ResultObject | Where-Object {($_.PID -eq $ProcID)}
		Return # In case of $ProcID -And $ProcName => PID takes preference
	}
	if ($ProcName) {
		$ResultObject | Where-Object {($_.ImageName -like "*$ProcName*")}
		Return # In case of $ProcID -And $ProcName => PID takes preference
	}
}