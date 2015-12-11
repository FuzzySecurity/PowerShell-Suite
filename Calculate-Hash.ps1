function Calculate-Hash {
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

    C:\PS> Calculate-Hash -Path C:\Some\File.path -Algorithm SHA512
    
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$false)]
        [ValidateSet($null,"MD5","RIPEMD160","SHA1","SHA256","SHA384","SHA512")]
        [string]$Algorithm=$null
    )
    
    # Make sure the path is valid
    $PathCheck = Test-Path $Path
    
    if($PathCheck -eq "True"){

        function HashCalc($HashAlgorithm){
            $FileStream = [system.io.file]::openread((resolve-path $Path))
            $HashObject = [System.Security.Cryptography.HashAlgorithm]::create($HashAlgorithm)
            $Hash = $HashObject.ComputeHash($FileStream)
            $FileStream.close()
            $FileStream.dispose()
            $Hash = [system.bitconverter]::tostring($Hash).replace('-','')
            echo "$HashAlgorithm : $Hash"
        }
    
        if($Algorithm){
            HashCalc $Algorithm
        }
        
        else{
            HashCalc "MD5"
            HashCalc "SHA256"
        }
        
    }
    
    else{
    
        echo "File path is not valid, maybe more coffee is the answer?"
        
    }
}