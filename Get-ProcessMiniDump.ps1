function Get-ProcessMiniDump {
<#
.SYNOPSIS
	Create process dump using Dbghelp::MiniDumpWriteDump.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER ProcID
	PID for the target process.

.PARAMETER Path
	Dump outfile path.

.EXAMPLE
	C:\PS> Get-ProcessMiniDump -ProcID 1234 -Path C:\Some\File\Path.out
#>

	[cmdletbinding()]
	param(
		[Parameter(Mandatory = $True)]
		[Int]$ProcID,
		[Parameter(Mandatory = $True)]
		[String]$Path
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	public class GetProcessMiniDump
	{
		[DllImport("Dbghelp.dll")]
		public static extern bool MiniDumpWriteDump(
			IntPtr hProcess,
			uint ProcessId,
			IntPtr hFile,
			int DumpType,
			IntPtr ExceptionParam,
			IntPtr UserStreamParam,
			IntPtr CallbackParam);
	}
"@

	# Check PID
	$IsValidProc = (Get-Process |Select -Expand Id) -Contains $ProcID
	if (!$IsValidProc) {
		Write-Verbose "[!] The specified PID does not exist!"
		$false
		Return
	}

	# Guesstimate if elevated privs are required
	$WhoAmI = [Environment]::UserName
	Write-Verbose "[?] Running as: $WhoAmI"
	$TargetPIDUser = (Get-WmiObject Win32_Process -Filter "ProcessId = $ProcID").GetOwner().User
	if ($WhoAmI -ne $TargetPIDUser) {
		Write-Verbose "[?] Administrator privileges required"
		$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
		if (!$IsAdmin) {
			Write-Verbose "[!] Administrator privileges not held!"
			$false
			Return
		} else {
			Write-Verbose "[>] Administrator privileges held"
		}
	}

	# Get handle for minidump outfile
	try {
		$FileStreamObject = [System.IO.File]::Create($Path)
	} catch {
		$ExceptionMsg = $_.Exception.Message
		Write-Verbose "[!] $ExceptionMsg"
		$false
		Return
	}

	# Full Process Dump
	#-----
	# MiniDumpIgnoreInaccessibleMemory = 0x00020000
	# MiniDumpWithDataSegs             = 0x00000001
	# MiniDumpWithFullMemory           = 0x00000002
	# MiniDumpWithFullMemoryInfo       = 0x00000800
	# MiniDumpWithHandleData           = 0x00000004
	# MiniDumpWithProcessThreadData    = 0x00000100
	# MiniDumpWithThreadInfo           = 0x00001000
	# MiniDumpWithTokenInformation     = 0x00040000
	# => 0x00061907
	#-----
	$hProc = (Get-Process -Id $ProcID).Handle
	$IsDumped = [GetProcessMiniDump]::MiniDumpWriteDump($hProc,$ProcID,$FileStreamObject.Handle,0x00061907,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero)
	$FileStreamObject.Close()
	if (!$IsDumped) {
		Write-Verbose "[!] Process dump failed!"
		Remove-Item $FileStreamObject.Name
		$false
	} else {
		Write-Verbose "[>] Process dump success!"
		$true
	}
}