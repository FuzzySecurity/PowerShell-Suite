function Expose-NetAPI {
<#
.SYNOPSIS

	Expose-NetAPI uses reflection to import .NET API classes into PowerShell.
	This includes internal private classes, such as
	Microsoft.Win32.UnsafeNativeMethods.

	The "Search" parameter provides a way to search loaded assemblies for
	partial matches on API names. Specifying the "Namespace" parameter
	restricts the search to the designated namespace. If the namespace does not
	exist in the current session this parameter will permanently load it.

.DESCRIPTION

	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER Enable

	Switch to indicate the enable parameter set name.

.PARAMETER Search

	Case insensitive string search for API names.

.PARAMETER Load

	Load specified assembly in the PowerShell session.

.PARAMETER Namespace

	.Net namespace, e.g. "System.Drawing".

.PARAMETER Assembly

	Dll corresponding to the specified TypeName.

.PARAMETER TypeName

	TypeName to be loaded from the specified Assembly.

.EXAMPLE

	# Search all loaded assemblies for "MessageBox".
	# The result is an object that can be piped.
	C:\PS> Expose-NetAPI -Search MessageBox |fl
	
	Assembly   : System.dll
	TypeName   : Microsoft.Win32.SafeNativeMethods
	Name       : MessageBox
	Definition : static int MessageBox(System.IntPtr hWnd, string text, string caption, int type)

.EXAMPLE

	# Not all namespaces are available by default in
	# PowerShell, MSDN/Google is your friend!
	C:\PS> Expose-NetAPI -Search bitmap

	[!] Search returned no results, try specifying the namespace!

	C:\PS> Expose-NetAPI -Search bitmap -Namespace System.Drawing

	Assembly            TypeName                          Name                        Definition
	--------            --------                          ----                        ----------
	System.Drawing.dll  System.Windows.Forms.DpiHelper    CreateResizedBitmap         static System.Drawing.Bitmap Crea...
	System.Drawing.dll  System.Windows.Forms.DpiHelper    ScaleBitmapLogicalToDevice  static void ScaleBitmapLogicalToD...
	System.Drawing.dll  System.Drawing.Bitmap             FromHbitmap                 static System.Drawing.Bitmap From...
	System.Drawing.dll  System.Drawing.BitmapSelector     CreateBitmap                static System.Drawing.Bitmap Crea...
	System.Drawing.dll  System.Drawing.Image              FromHbitmap                 static System.Drawing.Bitmap From...
	System.Drawing.dll  System.Drawing.SafeNativeMethods  CreateBitmap                static System.IntPtr CreateBitmap...
	System.Drawing.dll  System.Drawing.SafeNativeMethods  CreateCompatibleBitmap      static System.IntPtr CreateCompat...
	System.Drawing.dll  System.Drawing.SafeNativeMethods  IntCreateBitmap             static System.IntPtr IntCreateBit...
	System.Drawing.dll  System.Drawing.SafeNativeMethods  IntCreateCompatibleBitmap   static System.IntPtr IntCreateCom...
	System.Drawing.dll  System.Drawing.Imaging.Metafile   FromHbitmap                 static System.Drawing.Bitmap From...

.EXAMPLE

	# Often multiple options available with differing
	# definitions. Take care when selecting the desired
	# API.
	C:\PS> Expose-NetAPI -Search drawbutton |Select Assembly,TypeName,Name |ft
	
	Assembly                  TypeName                                           Name
	--------                  --------                                           ----
	System.Windows.Forms.dll  System.Windows.Forms.ButtonRenderer                DrawButton
	System.Windows.Forms.dll  System.Windows.Forms.ControlPaint                  DrawButton
	System.Windows.Forms.dll  System.Windows.Forms.DataGridViewButtonCell+Da...  DrawButton

.EXAMPLE

	# Take care when directly calling enable, a number
	# of assemblies are not loaded by default!
	C:\PS> Expose-NetAPI -Enable -Assembly System.Windows.Forms.dll -TypeName System.Windows.Forms.SafeNativeMethods

	[!] Unable to locate specified assembly!

	C:\PS> Expose-NetAPI -Load System.Windows.Forms
	True

	C:\PS> Expose-NetAPI -Enable -Assembly System.Windows.Forms.dll -TypeName System.Windows.Forms.SafeNativeMethods

	[+] Created $SystemWindowsFormsSafeNativeMethods!

.EXAMPLE

	# Once enabled the TypeName is exposed as a global
	# variable and can be used to call any API's it includes!
	C:\PS> Expose-NetAPI -Enable -Assembly System.dll -TypeName Microsoft.Win32.UnsafeNativeMethods |Out-Null
	C:\PS> Expose-NetAPI -Enable -Assembly System.dll -TypeName Microsoft.Win32.SafeNativeMethods |Out-Null
	C:\PS> $ModHandle = $MicrosoftWin32UnsafeNativeMethods::GetModuleHandle("kernel32.dll")
	C:\PS> $Kernel32Ref = New-Object System.Runtime.InteropServices.HandleRef([IntPtr]::Zero,$ModHandle)
	C:\PS> $Beep = $MicrosoftWin32UnsafeNativeMethods::GetProcAddress($Kernel32Ref, "Beep")
	C:\PS> $MicrosoftWin32SafeNativeMethods::MessageBox([IntPtr]::Zero,$("{0:X}" -f [int64]$Beep),"Beep",0)

#>

	param(
		[Parameter(ParameterSetName='Search', Mandatory = $True)]
		[string]$Search,
		[Parameter(ParameterSetName='Search', Mandatory = $False)]
		[string]$Namespace,
		[Parameter(ParameterSetName='Load', Mandatory = $True)]
		[string]$Load,
		[Parameter(ParameterSetName='Enable', Mandatory = $True)]
		[switch]$Enable,
		[Parameter(ParameterSetName='Enable', Mandatory = $True)]
		[string]$Assembly,
		[Parameter(ParameterSetName='Enable', Mandatory = $True)]
		[string]$TypeName
    )

	# Search functionality!
	if ($Search) {
		if ($Namespace) {
			# Load/search specified assembly
			# This will permanently load the assembly in the session!
			$Assemblies = [System.Reflection.Assembly]::LoadWithPartialName($Namespace)
			if (!$Assemblies) {
				echo "`n[!] Specified namespace can't be loaded!`n"
				Break
			}
		} else {
			# Traverse every, currently, loaded assembly
			$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
		}
		# Recurs $Assemblies for methods
		# Yes this loop is creepy!
		$ObjectArray = @()
		$Assemblies | ForEach-Object {
			$Assembly = $(($_.Location -Split "\\")[-1]); $_.GetTypes()| ForEach-Object {
				$_ | Get-Member -Static| Where-Object {
					($_.MemberType.ToString() -eq "Method") -And ($_.Name -like "*$Search*")
				} | ForEach-Object {
					$HashTable = @{
						Assembly = $Assembly
						TypeName = $_.TypeName
						Name = $_.Name
						Definition = $_.Definition
					}		
					$Object = New-Object PSObject -Property $HashTable
					$ObjectArray += $Object
				}
			} 2>$null
		}
		if (!$ObjectArray) {
			echo "`n[!] Search returned no results, try specifying the namespace!`n"
			Break
		} else {
			$ObjectArray| Select Assembly,TypeName,Name,Definition
		}
	}

	# Load specified assembly. This is necessary when directly calling
	# Enable on non-default namespaces!
	if($Load) {
		$CallResult = [System.Reflection.Assembly]::LoadWithPartialName($Load)
		if (!$CallResult) {
			$false
		} else {
			$true
		}
	}

	# Import functionality!
	if($Enable) {
		$GACRef = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($Assembly) }
		if (!$GACRef) {
			echo "`n[!] Unable to locate specified assembly!`n"
			Break
		}
		if (!$GACRef.GetType($TypeName)) {
			echo "`n[!] Unable to locate specified TypeName!`n"
		} else {
			New-Variable -Name $($TypeName -replace "\.","") -Scope Global -Value $GACRef.GetType($TypeName)
			echo "`n[+] Created `$$($TypeName -replace '\.','')!`n"
		}
	}
}