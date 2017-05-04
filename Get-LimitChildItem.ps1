function Get-LimitChildItem {
<#
.SYNOPSIS
	Depth limited wrapper for Get-ChildItem with basic filter functionality.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER Path
	Top level path (local or UNC).

.PARAMETER MaxDepth
	Folder depth.

.PARAMETER Filter
	Output filter string.

.EXAMPLE
	# Show all files up to 5 depth
	C:\PS> Get-LimitChildItem -Path \\NetworkHost\Share -MaxDepth 5

.EXAMPLE
	# Show only filenames containing "pass"
	C:\PS> Get-LimitChildItem -Path C:\Users\ -MaxDepth 10 -Filter "*pass*"
#>
	param(
		[Parameter(Mandatory = $true)]
		$Path,
		[UInt32]$MaxDepth=3,
		[String]$Filter = "*"
	)

	for ($i=1;$i-lt$($MaxDepth+1);$i++){
		$SearchPath = $Path + ("\*"*$i)
		$ResultObject = Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue
		$PathList = $ResultObject|Where {!$_.PSIsContainer} |ForEach-Object { if ($_.Name -like $Filter){$_.FullName}}
		$HashTable = @{
			Depth = $i
			Count = $PathList.Length
			Path = $PathList
		}
		$Object = New-Object PSObject -Property $HashTable
		# Object has more properties, use as required.
		# Print per depth..
		$Object.Path
	}
}