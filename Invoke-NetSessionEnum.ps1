function Invoke-NetSessionEnum {
<#
.SYNOPSIS

	Use Netapi32::NetSessionEnum to enumerate active sessions on domain joined machines.

.DESCRIPTION

	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	C:\PS> Invoke-NetSessionEnum -HostName SomeHostName

#>

	param (
        [Parameter(Mandatory = $True)]
		[string]$HostName
	)  

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SESSION_INFO_10
	{
		[MarshalAs(UnmanagedType.LPWStr)]public string OriginatingHost;
		[MarshalAs(UnmanagedType.LPWStr)]public string DomainUser;
		public uint SessionTime;
		public uint IdleTime;
	}
	
	public static class Netapi32
	{
		[DllImport("Netapi32.dll", SetLastError=true)]
			public static extern int NetSessionEnum(
				[In,MarshalAs(UnmanagedType.LPWStr)] string ServerName,
				[In,MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
				[In,MarshalAs(UnmanagedType.LPWStr)] string UserName,
				Int32 Level,
				out IntPtr bufptr,
				int prefmaxlen,
				ref Int32 entriesread,
				ref Int32 totalentries,
				ref Int32 resume_handle);
				
		[DllImport("Netapi32.dll", SetLastError=true)]
			public static extern int NetApiBufferFree(
				IntPtr Buffer);
	}
"@
	
	# Create SessionInfo10 Struct
	$SessionInfo10 = New-Object SESSION_INFO_10
	$SessionInfo10StructSize = [System.Runtime.InteropServices.Marshal]::SizeOf($SessionInfo10) # Grab size to loop bufptr
	$SessionInfo10 = $SessionInfo10.GetType() # Hacky, but we need this ;))
	
	# NetSessionEnum params
	$OutBuffPtr = [IntPtr]::Zero # Struct output buffer
	$EntriesRead = $TotalEntries = $ResumeHandle = 0 # Counters & ResumeHandle
	$CallResult = [Netapi32]::NetSessionEnum($HostName, "", "", 10, [ref]$OutBuffPtr, -1, [ref]$EntriesRead, [ref]$TotalEntries, [ref]$ResumeHandle)
	
	if ($CallResult -ne 0){
		echo "Mmm something went wrong!`nError Code: $CallResult"
	}
	
	else {
	
		if ([System.IntPtr]::Size -eq 4) {
			echo "`nNetapi32::NetSessionEnum Buffer Offset  --> 0x$("{0:X8}" -f $OutBuffPtr.ToInt32())"
		}
		else {
			echo "`nNetapi32::NetSessionEnum Buffer Offset  --> 0x$("{0:X16}" -f $OutBuffPtr.ToInt64())"
		}
		
		echo "Result-set contains $EntriesRead session(s)!"
	
		# Change buffer offset to int
		$BufferOffset = $OutBuffPtr.ToInt64()
		
		# Loop buffer entries and cast pointers as SessionInfo10
		for ($Count = 0; ($Count -lt $EntriesRead); $Count++){
			$NewIntPtr = New-Object System.Intptr -ArgumentList $BufferOffset
			$Info = [system.runtime.interopservices.marshal]::PtrToStructure($NewIntPtr,[type]$SessionInfo10)
			$Info
			$BufferOffset = $BufferOffset + $SessionInfo10StructSize
		}
		
		echo "`nCalling NetApiBufferFree, no memleaks here!"
		[Netapi32]::NetApiBufferFree($OutBuffPtr) |Out-Null
	}
}