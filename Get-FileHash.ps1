function Get-FileHash {
<#
.SYNOPSIS
 
    PowerShell v2 compatible script to calculate file hashes.
 
.PARAMETER Path
 
    Path to file.
 
.PARAMETER Algorithm
 
    Algorithm to use: MD5, RIPEMD160, SHA1, SHA256, SHA384, SHA512. If the algorithm parameter is not specified both MD5 and SHA256 will be shown.
        
.DESCRIPTION
 
        Author: Ruben Boonen (@FuzzySec)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
 
.EXAMPLE
 
    C:\PS> Get-FileHash -Path "C:\File1.txt","C:\File2.txt" -Algorithm "SHA1", "MD5"
 
#>
 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string[]]$Path,
 
        [Parameter(Mandatory=$false)]
        [ValidateSet("MD5","RIPEMD160","SHA1","SHA256","SHA384","SHA512")]
        [string[]]$Algorithm="MD5"
    )
 
    foreach ($file in $Path) {
        if(Test-Path -Path $file -PathType Leaf){
            foreach ($hashAlgorithm in $Algorithm) {
                try {
                    $FileStream = [system.IO.File]::OpenRead($file)
                    $HashObject = [System.Security.Cryptography.HashAlgorithm]::create($hashAlgorithm)
                    $Hash = $HashObject.ComputeHash($FileStream)
                    $Hash = [System.BitConverter]::ToString($Hash).replace('-','')
                    New-Object -TypeName PSObject -Property @{"Path"=$file;"HashAlgorithm"=$hashAlgorithm;"Hash"=$Hash}
                }
                catch {
                }
                finally {
                    $FileStream.Close()
                    $FileStream.Dispose()
                }
            }
        }
        else
        {
            Write-Error "File path is not valid, maybe more coffee is the answer?"
        }
    }
}
