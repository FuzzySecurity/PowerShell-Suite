function Check-VTFile {
<#
.SYNOPSIS

    Submit SHA256 hash of a file to Virus Total and retrieve the scan report if the hash is known.

.PARAMETER Path

    Path to file.
	
.DESCRIPTION

	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE

    C:\PS> Check-VTFile -Path C:\Some\File.path
    
#>

	param (
        [Parameter(Mandatory = $True)]
		[string]$Path
	)

    # Virus Total parameters
    $VTApiKey = "" # API key here!
    $APIRequestURL = "https://www.virustotal.com/vtapi/v2/file/report"

    # Create SHA256 file hash
    $FileStream = [system.io.file]::openread((resolve-path $Path))
    $SHAObject = [System.Security.Cryptography.HashAlgorithm]::create("sha256")
    $hash = $SHAObject.ComputeHash($FileStream)
    $FileStream.close()
    $FileStream.dispose()
    $hash = [system.bitconverter]::tostring($hash).replace('-','')

    # Submit hash to VirusTotal
    function HTTP-JSON($APIRequestURL,$parameters){ 
        $http_request = New-Object -ComObject Msxml2.XMLHTTP 
        $http_request.open("POST", $APIRequestURL, $false) 
        $http_request.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
        $http_request.setRequestHeader("Content-length", $parameters.length); 
        $http_request.setRequestHeader("Connection", "close") 
        $http_request.send($parameters) 
        $script:result = $http_request.responseText
    }
    
    HTTP-JSON "https://www.virustotal.com/vtapi/v2/file/report" "resource=$hash&apikey=$VTApiKey"
    
    # Turn VirusTotal JSON response into PowerShell object
	[System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions") | Out-Null
	$Serialize = New-Object System.Web.Script.Serialization.JavaScriptSerializer
	$Response = $Serialize.DeserializeObject($result)

    echo "`n[>] SHA256 File Hash: $hash"
    
    # If hash not found on Virus Total
    if ($Response.verbose_msg -Like '*not among*') {
        echo "[+] File hash not known by Virus Total!"
    }

    # Hash found on Virus Total
    else {
        # Set object properties as variable for output formatting
        $ResponseDate = $Response.scan_date
        $ResponsePositives = $Response.positives
        $ResponseTotal = $Response.total

        echo "[+] File hash known by Virus Total!"
        echo "[>] Last Scan Date: $ResponseDate"
        echo "[>] Detection Rate: $ResponsePositives of $ResponseTotal"

        # Check if any AV flag flag the file
        if ($ResponsePositives -ne 0) {
            # Extract AV name & Result string
            echo "[+] AV Malware Identification"
            # Add name and result to hashtable if the file was flagged
            $AVOutputTable = @{}
            foreach ($Instance in $Response.scans.Keys) {
                $AV = $Instance
                $AVResult =  $Response.scans.$AV.result
                if ($AVResult){ 
                    $AVOutputTable.$AV = $AVResult
                }
            }$AVOutputTable # Print hashtable
        }
    }
}