function Get-OSTokenInformation {
<#
.SYNOPSIS
	Get-OSTokenInformation uses a variety of API's to pull in all (accessible) user tokens and queries them for details.

	Notes:
	- This is not a perfect process as you may not be able to access all processes/threads and they may disappear
	  between the time the script identifies them and later tries to poll the data.
	- Calling Get-AuthenticodeSignature on all binary paths is intensive so I commented out lines 611
	  and 618 to speed up the scanner. Re-enable as required.
	- The function impersonates SYSTEM using SetThreadToken but this requires the PowerShell apartment state
	  to be STA. This is only an issue on Win7 & 2k8.
	- If the function returns $false please use "-Verbose" for more information.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER Brief
	If the "-Brief" flag is specified the output is limited to a select number of fields and the results are displayed
	in a table format.

.EXAMPLE
	C:\PS> $OsTokens = Get-OSTokenInformation

	C:\PS> $OsTokens.Count
	136

	C:\PS> $OsTokens[10]

	PassMustChange      : N/A
	ProcessCompany      : Microsoft Corporation
	AuthPackage         : NTLM
	TokenType           : TokenPrimary
	PID                 : 5876
	LastSuccessfulLogon : N/A
	Session             : 1
	LastFailedLogon     : N/A
	ProcessPath         : C:\Windows\system32\backgroundTaskHost.exe
	LogonServer         : MSEDGEWIN10
	Sid                 : S-1-5-21-4233833229-2203495600-2027003190-1000
	ProcessAuthenticode : Valid
	User                : MSEDGEWIN10\IEUser
	LoginTime           : 4/16/2018 9:52:20 PM
	TokenPrivilegeCount : 5
	TokenPrivileges     : {SeShutdownPrivilege, SeChangeNotifyPrivilege, SeUndockPrivilege,
	                      SeIncreaseWorkingSetPrivilege...}
	Process             : backgroundTaskHost
	PassLastSet         : 10/17/2017 6:13:19 PM
	ImpersonationType   : N/A
	TID                 : Primary
	TokenGroups         : {MSEDGEWIN10\IEUser, MSEDGEWIN10\None, Everyone, NT AUTHORITY\Local account and member of
	                      Administrators group...}
	LogonType           : Interactive
	GroupCount          : 14
	Elevated            : No

.EXAMPLE
	C:\PS> Get-OSTokenInformation -Brief

	Process               PID TID     Elevated ImpersonationType     User
	-------               --- ---     -------- -----------------     ----
	ApplicationFrameHost 5820 Primary No       N/A                   MSEDGEWIN10\IEUser
	backgroundTaskHost   1076 Primary No       N/A                   MSEDGEWIN10\IEUser
	backgroundTaskHost   1960 Primary No       N/A                   MSEDGEWIN10\IEUser
	backgroundTaskHost   7860 Primary No       N/A                   MSEDGEWIN10\IEUser
	CompatTelRunner       680 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
	CompatTelRunner      6916 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
	CompatTelRunner      8488 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
	svchost              3572 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
	svchost              3900 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
	svchost              4292 Primary Yes      N/A                   NT AUTHORITY\SYSTEM
	svchost              4292 144     No       SecurityImpersonation MSEDGEWIN10\IEUser
	svchost              4292 7704    No       SecurityImpersonation MSEDGEWIN10\IEUser
	svchost              4292 1404    No       SecurityImpersonation MSEDGEWIN10\IEUser
	svchost              4464 Primary No       N/A                   MSEDGEWIN10\IEUser
	svchost              4556 Primary No       N/A                   MSEDGEWIN10\IEUser
	[... Snip ...]

#>
	
	[CmdletBinding(DefaultParameterSetName="Detailed")]
	param(
		[Parameter(ParameterSetName='Brief', Mandatory = $True)]
		[switch]$Brief,
		[Parameter(ParameterSetName='Statistics', Mandatory = $True)]
		[switch]$Statistics
	)
	
	# Native API Definitions
	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	public enum TOKEN_TYPE : int
	{
		TokenPrimary = 1,
		TokenImpersonation
	}
	
	public enum SECURITY_IMPERSONATION_LEVEL : int
	{
		SecurityAnonymous = 0,
		SecurityIdentification,
		SecurityImpersonation,
		SecurityDelegation
	}
	
	public enum SECURITY_LOGON_TYPE : int
	{
		Session0 = 0, /// This type is unknown
		Interactive = 2,
		Network,
		Batch,
		Service,
		Proxy,
		Unlock,
		NetworkCleartext,
		NewCredentials,
		RemoteInteractive,
		CachedInteractive,
		CachedRemoteInteractive,
		CachedUnlock
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct UNICODE_STRING
	{
		public UInt16 Length;
		public UInt16 MaximumLength;
		public IntPtr Buffer;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct LUID
	{
		public UInt32 LowPart;
		public Int32 HighPart;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct LARGE_INTEGER
	{
		public UInt32 LowPart;
		public UInt32 HighPart;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct TOKEN_STATISTICS
	{
		public LUID TokenId;
		public LUID AuthenticationId;
		public LARGE_INTEGER ExpirationTime;
		public UInt32 TokenType;
		public UInt32 ImpersonationLevel;
		public UInt32 DynamicCharged;
		public UInt32 DynamicAvailable;
		public UInt32 GroupCount;
		public UInt32 PrivilegeCount;
		public LUID ModifiedId;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct TOKEN_ELEVATION
	{
		public UInt32 TokenIsElevated;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct LSA_LAST_INTER_LOGON_INFO
	{
		public LARGE_INTEGER LastSuccessfulLogon;
		public LARGE_INTEGER LastFailedLogon;
		public UInt32 FailedAttemptCountSinceLastSuccessfulLogon;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_LOGON_SESSION_DATA
	{
		public UInt32 Size;
		public LUID LoginID;
		public UNICODE_STRING Username;
		public UNICODE_STRING LoginDomain;
		public UNICODE_STRING AuthenticationPackage;
		public UInt32 LogonType;
		public UInt32 Session;
		public IntPtr Sid;
		public LARGE_INTEGER LoginTime;
		public UNICODE_STRING LoginServer;
		public UNICODE_STRING DnsDomainName;
		public UNICODE_STRING Upn;
		public IntPtr UserFlags; /// This is a hack because on x64
                                         /// there is 4-byte padding here..
                                         /// The UserFlags type is UInt32.
		public LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
		public UNICODE_STRING LogonScript;
		public UNICODE_STRING ProfilePath;
		public UNICODE_STRING HomeDirectory;
		public UNICODE_STRING HomeDirectoryDrive;
		public LARGE_INTEGER LogoffTime;
		public LARGE_INTEGER KickOffTime;
		public LARGE_INTEGER PasswordLastSet;
		public LARGE_INTEGER PasswordCanChange;
		public LARGE_INTEGER PasswordMustChange;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SID_AND_ATTRIBUTES
	{
		public IntPtr Sid;
		public UInt32 Attributes;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct LUID_AND_ATTRIBUTES
	{
		public LUID Luid;
		public UInt32 Attributes;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct TOKEN_GROUPS_AND_PRIVILEGES
	{
		public UInt32 SidCount;
		public UInt32 SidLength;
		public IntPtr Sids;
		public UInt32 RestrictedSidCount;
		public UInt32 RestrictedSidLength;
		public IntPtr RestrictedSids;
		public UInt32 PrivilegeCount;
		public UInt32 PrivilegeLength;
		public IntPtr Privileges;
		public LUID AuthenticationId;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SYSTEMTIME
	{
		public Int16 wYear;
		public Int16 wMonth;
		public Int16 wDayOfWeek;
		public Int16 wDay;
		public Int16 wHour;
		public Int16 wMinute;
		public Int16 wSecond;
		public Int16 wMilliseconds;
	}
	
	public static class TokenEnum
	{
		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(
			UInt32 processAccess,
			bool bInheritHandle,
			UInt32 processId);
	
		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenThread(
			UInt32 dwDesiredAccess,
			bool bInheritHandle,
			UInt32 dwThreadId);
	
		[DllImport("kernel32.dll")]
		public static extern bool CloseHandle(
			IntPtr hObject);
	
		[DllImport("kernel32.dll")]
		public static extern bool FileTimeToSystemTime(
			ref LARGE_INTEGER lpFileTime,
			ref SYSTEMTIME lpSystemTime);
	
		[DllImport("secur32.dll")]
		public static extern UInt32 LsaGetLogonSessionData(
			IntPtr LogonId,
			ref IntPtr ppLogonSessionData);
	
		[DllImport("advapi32.dll")]
		public static extern bool OpenProcessToken(
			IntPtr ProcessHandle, 
			int DesiredAccess,
			ref IntPtr TokenHandle);
	
		[DllImport("advapi32.dll")]
		public static extern bool OpenThreadToken(
			IntPtr ThreadHandle, 
			int DesiredAccess,
			bool OpenAsSelf,
			ref IntPtr TokenHandle);
	
		[DllImport("advapi32.dll")]
		public static extern bool GetTokenInformation(
			IntPtr TokenHandle,
			UInt32 TokenInformationClass,
			IntPtr TokenInformation,
			UInt32 TokenInformationLength,
			ref UInt32 ReturnLength);
	
		[DllImport("advapi32.dll")]
		public extern static bool DuplicateToken(
			IntPtr hExistingToken,
			UInt32 ImpersonationLevel,
			ref IntPtr phNewToken);
	
		[DllImport("advapi32.dll")]
		public static extern bool SetThreadToken(
			IntPtr Thread,
			IntPtr Token);
	
		[DllImport("advapi32.dll")]
		public static extern bool RevertToSelf();
	
		[DllImport("advapi32.dll")]
		public static extern bool LookupAccountSidW(
			IntPtr lpSystemName,
			IntPtr Sid,
			IntPtr lpName,
			ref UInt32 cchName,
			IntPtr ReferencedDomainName,
			ref UInt32 cchReferencedDomainName,
			ref UInt32 peUse);
	
		[DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
		public static extern bool ConvertSidToStringSid(
			IntPtr Thread,
			ref string pStringSid);
	
		[DllImport("advapi32.dll")]
		public static extern bool LookupPrivilegeName(
			string lpSystemName,
			IntPtr lpLuid,
			System.Text.StringBuilder lpName,
			ref int cchName);
	
		[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
		public static extern bool LookupAccountSid(
			string lpSystemName,
			IntPtr Sid,
			System.Text.StringBuilder lpName,
			ref UInt32 cchName,
			System.Text.StringBuilder ReferencedDomainName,
			ref UInt32 cchReferencedDomainName,
			ref UInt32 peUse);
	}
"@
	
	function Return-PrimaryToken {
		param($TargetPID)
		# Open process => PROCESS_QUERY_INFORMATION
		$hProcess = [TokenEnum]::OpenProcess(0x400, $true, $TargetPID)
		if ($hProcess -eq [IntPtr]::Zero) {
			# If Admin this should only fail for protected procs
			# this is a fail
			$false
		} else {
			# Open process token => TOKEN_ALL_ACCESS
			$hPrimaryToken = [IntPtr]::Zero
			$CallResult = [TokenEnum]::OpenProcessToken($hProcess,0xf01ff,[ref]$hPrimaryToken)
			if (!$CallResult -Or $hPrimaryToken -eq [IntPtr]::Zero) {
				# this is a fail
				$false
			} else {
				# this is success
				$TokenResult = "$hPrimaryToken-Primary"
				$TokenResult
			}
			# Close handle to the process
			$CallResult = [TokenEnum]::CloseHandle($hProcess)
		}
	}

	function Return-ThreadTokens {
		param($TargetPID)
		# Get all proc TID's
		$ProcTIDs = (Get-Process -Id $TargetPID -ErrorAction SilentlyContinue).Threads |Select-Object -ExpandProperty Id
		# Create result array
		$hThreadTokenArray = @()
		# Loop TID's
		$ProcTIDs| ForEach-Object {
			# Open thread => THREAD_ALL_ACCESS
			$hThread = [TokenEnum]::OpenThread(0x1f03ff,$false,$_)
			if ($hThread -eq [IntPtr]::Zero) {
				# this is fail
				$ThreadResult = $false
			} else {
				# Open thread token => TOKEN_ALL_ACCESS
				$hThreadToken = [IntPtr]::Zero
				$CallResult = [TokenEnum]::OpenThreadToken($hThread,0xf01ff,$false,[ref]$hThreadToken)
				if (!$CallResult) {
					# this can fail because: 
					# - No impersonation (ERROR_NO_TOKEN), this is ok!
					# - Thread closed (ERROR_INVALID_PARAMETER), this is ok!
					# - Anything else, like access denied, this is fail!
					$ThreadResult = $false
				} else {
					# this is success
					$ThreadResult = $true
					# Close handle to the thread
					$CallResult = [TokenEnum]::CloseHandle($hThread)
				}
			}
			# If success add handle to array
			if ($ThreadResult) {
				$hThreadTokenArray += "$hThreadToken-$($_)"
			}
		}
		# Return Result
		$hThreadTokenArray
	}

	function Return-TokenInformation {
		param($hToken,$TID,$ProcID)
		# (1) Get token statistics => TokenStatistics (10)
		$TokenStats = New-Object TOKEN_STATISTICS
		$TokenStatsSize = [System.Runtime.InteropServices.Marshal]::SizeOf($TokenStats)
		$TokenStats = $TokenStats.GetType()
		[IntPtr]$pTokenStats = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenStatsSize)
		[UInt32]$Length = 0
		$CallResult = [TokenEnum]::GetTokenInformation($hToken,10,$pTokenStats,$TokenStatsSize,[ref]$Length)
		if (!$CallResult) {
			# Some logic here
			$ResTokenPrivileges = "False"
			$ResGroupCount = "False"
			$ResTokenType = "False"
			$ResImpersonation = "False"
		} else {
			# TokenId            : LUID
			# AuthenticationId   : LUID
			# ExpirationTime     : LARGE_INTEGER
			# TokenType          : 1
			# ImpersonationLevel : 0
			# DynamicCharged     : 4096
			# DynamicAvailable   : 3976
			# GroupCount         : 18
			# PrivilegeCount     : 5
			# ModifiedId         : LUID
			$TokenStatsStruct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pTokenStats,[Type]$TokenStats)
			$ResTokenPrivileges = $TokenStatsStruct.PrivilegeCount
			$ResGroupCount = $TokenStatsStruct.GroupCount
			$ResTokenType = [TOKEN_TYPE]$TokenStatsStruct.TokenType
			if ($TokenStatsStruct.TokenType -eq 2) {
				$ResImpersonation = [SECURITY_IMPERSONATION_LEVEL]$TokenStatsStruct.ImpersonationLevel
			} else {
				$ResImpersonation = "N/A"
			}
		
			# Query logon session info from LUID
			$LUID = New-Object LUID
			[IntPtr]$pLUID = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($LUID))
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenStatsStruct.AuthenticationId, $pLUID, $false)
			$SessionDataStruct = [IntPtr]::Zero
			$CallResult = [TokenEnum]::LsaGetLogonSessionData($pLUID,[ref]$SessionDataStruct)
			if ($CallResult -ne 0 -Or $SessionDataStruct -eq [IntPtr]::Zero) {
				# Some logic here
				$ResTokenUser = "False"
				$ResLogonType = "False"
				$ResSession = "False"
				$ResLoginTime = "False"
				$ResStringSid = "False"
				$ResAuthPackage = "False"
				$ResLogonServer = "False"
				$ResPassLastSet = "False"
				$ResPassMustChange = "False"
				$ResLastSuccess = "False"
				$ResLastFail = "False"
			} else {
				# Size                  : 272
				# LoginID               : LUID
				# Username              : UNICODE_STRING
				# LoginDomain           : UNICODE_STRING
				# AuthenticationPackage : UNICODE_STRING
				# LogonType             : 2
				# Session               : 1
				# Sid                   : 1369141805328
				# LoginTime             : LARGE_INTEGER
				# LoginServer           : UNICODE_STRING
				# DnsDomainName         : UNICODE_STRING
				# Upn                   : UNICODE_STRING
				# UserFlags             : 33056
				# LastLogonInfo         : LSA_LAST_INTER_LOGON_INFO
				# LogonScript           : UNICODE_STRING
				# ProfilePath           : UNICODE_STRING
				# HomeDirectory         : UNICODE_STRING
				# HomeDirectoryDrive    : UNICODE_STRING
				# LogoffTime            : LARGE_INTEGER
				# KickOffTime           : LARGE_INTEGER
				# PasswordLastSet       : LARGE_INTEGER
				# PasswordCanChange     : LARGE_INTEGER
				# PasswordMustChange    : LARGE_INTEGER
				$SecurityLogonSessionData = New-Object SECURITY_LOGON_SESSION_DATA
				$SecurityLogonSessionData = $SecurityLogonSessionData.GetType()
				$TokenLogonDataStruct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SessionDataStruct,[Type]$SecurityLogonSessionData)
			
				$Domain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($TokenLogonDataStruct.LoginDomain.Buffer)
				$User = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($TokenLogonDataStruct.Username.Buffer)

				# If local account -> lookup
				if ($User -ieq "$($env:COMPUTERNAME)`$") {
					[UInt32]$Size = 100
					[UInt32]$NumUsernameChar = $Size / 2
					[UInt32]$NumDomainChar = $Size / 2
					[UInt32]$SidNameUse = 0
					$UsernameBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
					$DomainBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
					$CallResult = [TokenEnum]::LookupAccountSidW([IntPtr]::Zero,$TokenLogonDataStruct.Sid,$UsernameBuffer,[ref]$NumUsernameChar,$DomainBuffer,[ref]$NumDomainChar,[ref]$SidNameUse)
					if ($CallResult) {
						$Domain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($DomainBuffer)
						$User = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($UsernameBuffer)
					}
				}

				$ResTokenUser = "$Domain\$User"
				$ResLogonType = [SECURITY_LOGON_TYPE]$TokenLogonDataStruct.LogonType
				$ResSession = $TokenLogonDataStruct.Session
				$ResLoginTime = Get-SystemTimeFromFileTime -LargeInteger $TokenLogonDataStruct.LoginTime
				$ResStringSid = Get-StringSidFromSid -PSid $TokenLogonDataStruct.Sid
				$ResAuthPackage = Get-UnicodeStringBuffer -Length $TokenLogonDataStruct.AuthenticationPackage.Length -Buffer $TokenLogonDataStruct.AuthenticationPackage.Buffer
				$ResLogonServer = Get-UnicodeStringBuffer -Length $TokenLogonDataStruct.LoginServer.Length -Buffer $TokenLogonDataStruct.LoginServer.Buffer
				$ResPassLastSet = Get-SystemTimeFromFileTime -LargeInteger $TokenLogonDataStruct.PasswordLastSet
				$ResPassMustChange = Get-SystemTimeFromFileTime -LargeInteger $TokenLogonDataStruct.PasswordMustChange
				$ResLastSuccess = Get-SystemTimeFromFileTime -LargeInteger $TokenLogonDataStruct.LastLogonInfo.LastSuccessfulLogon
				$ResLastFail = Get-SystemTimeFromFileTime -LargeInteger $TokenLogonDataStruct.LastLogonInfo.LastFailedLogon
			}

			# (2) Get token elevation status => TokenElevation (20)
			$TokenElevation = New-Object TOKEN_ELEVATION
			$TokenElevationSize = [System.Runtime.InteropServices.Marshal]::SizeOf($TokenElevation)
			$TokenElevation = $TokenElevation.GetType() # Not necessary?
			[IntPtr]$pTokenElevation = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenElevationSize)
			[UInt32]$Length = 0
			$CallResult = [TokenEnum]::GetTokenInformation($hToken,20,$pTokenElevation,$TokenElevationSize,[ref]$Length)
			if (!$CallResult) {
				# Some logic here
				$ResElevated = "False"
			} else {
				# Anything not "0" is elevated
				$TokenIsElevated = [System.Runtime.InteropServices.Marshal]::ReadInt32($pTokenElevation)
				if ($TokenIsElevated -eq 0) {
					$ResElevated = "No"
				} else {
					$ResElevated = "Yes"
				}
			}

			# (3) Get token groups & privileges => TokenGroupsAndPrivileges (13)
			[UInt32]$Length = 0
			$CallResult = [TokenEnum]::GetTokenInformation($hToken,13,[IntPtr]::Zero,0,[ref]$Length) # Get Alloc length
			[IntPtr]$pTokenGroupsAndPrivileges = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Length) # Alloc buffer
			$CallResult = [TokenEnum]::GetTokenInformation($hToken,13,$pTokenGroupsAndPrivileges,$Length,[ref]$Length) # Call function
			$TokenGroupsAndPrivileges = New-Object TOKEN_GROUPS_AND_PRIVILEGES
			$TokenGroupsAndPrivileges = $TokenGroupsAndPrivileges.GetType()
			$TokenGroupsAndPrivilegesStruct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($pTokenGroupsAndPrivileges,[Type]$TokenGroupsAndPrivileges)
			if (!$CallResult) {
				# Some logic here
				$ResTokenPrivs = "False"
				$ResTokenGroups = "False"
			} else {
				# Create Privilege array & populate
				[String[]]$ResTokenPrivs = @()
				$PrivilegeCount = $TokenGroupsAndPrivilegesStruct.PrivilegeCount
				for ($i=0;$i -lt $PrivilegeCount;$i++) {
					$pLUID = $($TokenGroupsAndPrivilegesStruct.Privileges.ToInt64() + (0xC*$i))
					$cchName = 0
					$CallResult = [TokenEnum]::LookupPrivilegeName($null, [IntPtr]$pLUID, $null, [ref]$cchName)
					$lpName = New-Object -TypeName System.Text.StringBuilder
					$lpName.EnsureCapacity($cchName+1) |Out-Null
					$CallResult = [TokenEnum]::LookupPrivilegeName($null, [IntPtr]$pLUID, $lpName, [ref]$cchName)
					$ResTokenPrivs += $lpName
				}

				# Create Group array & populate
				[String[]]$ResTokenGroups = @()
				$GroupCount = $TokenGroupsAndPrivilegesStruct.SidCount
				for ($i=0;$i -lt $GroupCount;$i++) {
					if ([System.IntPtr]::Size -eq 4) {
						$pSnA = $($TokenGroupsAndPrivilegesStruct.Sids.ToInt64() + (0x8*$i))
						$pSID = [System.Runtime.InteropServices.Marshal]::ReadInt32($pSnA)
					} else {
						$pSnA = $($TokenGroupsAndPrivilegesStruct.Sids.ToInt64() + (0x10*$i))
						$pSID = [System.Runtime.InteropServices.Marshal]::ReadInt64($pSnA)
					}

					$cchName = 0
					$cchReferencedDomainName = 0
					$peUse = 0
					$CallResult = [TokenEnum]::LookupAccountSid($null, [IntPtr]$pSID, $null, [ref]$cchName, $null, [ref]$cchReferencedDomainName, [ref]$peUse)
					$lpName = New-Object -TypeName System.Text.StringBuilder
					$lpName.EnsureCapacity($cchName+1) |Out-Null
					$ReferencedDomainName = New-Object -TypeName System.Text.StringBuilder
					$ReferencedDomainName.EnsureCapacity($cchReferencedDomainName+1) |Out-Null
					$CallResult = [TokenEnum]::LookupAccountSid($null, [IntPtr]$pSID, $lpName, [ref]$cchName, $ReferencedDomainName, [ref]$cchReferencedDomainName, [ref]$peUse)

					if ($CallResult) {
						if ($ReferencedDomainName.Length -ne 0) {
							$ResTokenGroups += "$ReferencedDomainName\$lpName"
						} else {
							$ResTokenGroups += $lpName
						}
					} else {
						$ResTokenGroups += "Group Lookup Failed"
					}
				}
			}
		}

		# PID path and Authenticode Signature
		$FilePath = $((Get-Process -Id $ProcID -ErrorAction SilentlyContinue).Path)
		#$SignatureState = Get-AuthenticodeSignatureFromPath -FilePath $FilePath

		if ($ResTokenPrivileges -ne $false) {
			$HashTable = @{
				Process = $((Get-Process -Id $ProcID -ErrorAction SilentlyContinue).Name)
				ProcessPath = $FilePath
				ProcessCompany = $((Get-Process -Id $ProcID -ErrorAction SilentlyContinue).Company)
				#ProcessAuthenticode = $SignatureState
				PID = $ProcID
				TokenPrivilegeCount = $ResTokenPrivileges
				User = $ResTokenUser
				LogonType = $ResLogonType
				Session = $ResSession
				Elevated = $ResElevated
				TokenType = $ResTokenType
				ImpersonationType = $ResImpersonation
				LoginTime = $ResLoginTime
				Sid = $ResStringSid
				AuthPackage = $ResAuthPackage
				LogonServer = $ResLogonServer
				PassLastSet = $ResPassLastSet
				PassMustChange = $ResPassMustChange
				LastSuccessfulLogon = $ResLastSuccess
				LastFailedLogon = $ResLastFail
				GroupCount = $ResGroupCount
				TokenPrivileges = $ResTokenPrivs
				TokenGroups = $ResTokenGroups
				TID = $TID
			}
			New-Object PSObject -Property $HashTable
		}
	}

	function Get-SystemTimeFromFileTime {
		param($LargeInteger)

		# LARGE_INTEGER is equivalent to FILETIME in this case
		if ($LargeInteger.HighPart -eq 0 -Or $LargeInteger.HighPart -eq 0x7FFFFFFF) {
			$DateTime = "N/A"
		} else {
			$SystemTimeStruct = New-Object SYSTEMTIME
			$CallResult = [TokenEnum]::FileTimeToSystemTime([ref]$LargeInteger, [ref]$SystemTimeStruct)
			if ($CallResult) {
				$DateTime = New-Object DateTime $SystemTimeStruct.wYear,$SystemTimeStruct.wMonth,$SystemTimeStruct.wDay,$SystemTimeStruct.wHour,$SystemTimeStruct.wMinute,$SystemTimeStruct.wSecond
			} else {
				$DateTime = "N/A"
			}
		}
		$DateTime
	}

	function Get-StringSidFromSid {
		param($PSid)

		$StringSidContainer = [String]::Empty
		$CallResult = [TokenEnum]::ConvertSidToStringSid($PSid,[ref]$StringSidContainer)
		if ($CallResult) {
			$StringSid = $StringSidContainer
		} else {
			$StringSid = "N/A"
		}
		$StringSid
	}

	function Get-UnicodeStringBuffer {
		param($Length,$Buffer)

		if ($Length -gt 0) {
			$BufferToString = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Buffer)
		} else {
			$BufferToString = "N/A"
		}
		$BufferToString
	}

	function Get-AuthenticodeSignatureFromPath {
		param($FilePath)

		# Not all PID's will have a file path to query
		if ($FilePath) {
			$AuthenticodeState = $((Get-AuthenticodeSignature -FilePath $FilePath).Status)
		} else {
			$AuthenticodeState = "N/A"
		}
		$AuthenticodeState
	}

	function Get-System {

		# SetThreadToken requires PowerShell to run with a single-threaded apartment state (STA)
		# Note: Win7 is the only version of Windows that runs PowerShell in MTA by default
		[String]$ApartmentState = [Threading.Thread]::CurrentThread.GetApartmentState()
		if ($ApartmentState -ne "STA") {
			Write-Verbose "[!] Please relaunch PowerShell with STA => powershell -sta"
			$false
			Return
		}

		# Verify our Admin PowerShell has SeDebugPrivilege
		$Whoami = whoami /priv /fo csv |ConvertFrom-Csv
		$SeDebugPrivilegeState = $null
		ForEach ($Privilege in $Whoami) {
			if ($Privilege."Privilege Name" -contains "SeDebugPrivilege") {
				$SeDebugPrivilegeState = $Privilege.State
			}
		}
		if (!$SeDebugPrivilegeState -Or $SeDebugPrivilegeState -eq "Disabled") {
			Write-Verbose "[!] SeDebugPrivilege not held"
			$false
			Return
		}

		# Open LSASS token
		$hLSASS = (Get-Process -Name lsass).Handle
		$hLSASSToken = [IntPtr]::Zero
		# 0x6 = TOKEN_IMPERSONATE|TOKEN_DUPLICATE
		$CallResult = [TokenEnum]::OpenProcessToken($hLSASS, 0x6, [ref]$hLSASSToken)
		if ($hLSASSToken -eq [IntPtr]::Zero) {
			Write-Verbose "[!] Unable to open LSASS process token"
			$false
			Return
		}

		# Duplicate token
		$hDuplicateToken = [IntPtr]::Zero
		# 0x2 = SecurityImpersonation
		$CallResult = [TokenEnum]::DuplicateToken($hLSASSToken, 0x2, [ref]$hDuplicateToken)
		if ($hDuplicateToken -eq [IntPtr]::Zero) {
			Write-Verbose "[!] Unable to duplicate LSASS token"
			$false
			Return
		}

		# Assign the LSASS impersonation token to the current thread
		$CallResult = [TokenEnum]::SetThreadToken([IntPtr]::Zero, $hDuplicateToken)
		$UserContext = [Environment]::UserName
		if ($UserContext -ne "SYSTEM") {
			Write-Verbose "[!] Failed to impersonate SYSTEM in the current thread"
			$false
			Return
		} else {
			$true
		}
	}

	# Main function logic

	# Read ParameterSetName
	$Mode = $PSCmdlet.ParameterSetName

	# We need Admin->SYSTEM to enumerate all tokens
	$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
	if (!$IsAdmin) {
		Write-Verbose "[!] Administrator privileges required"
		$false
		Return
	}

	# Use SetThreadToken to impersonate SYSTEM in the current thread
	$IsSYSTEM = Get-System
	if (!$IsSYSTEM) {
		$false
		Return
	}

	# Get process list
	$ProcessList = Get-Process

	# Loop processes
	$ResultObject = @()
	for ($i=0;$i -lt $ProcessList.Length;$i++) {
		$ProcessTokenArray = @()
		$PrimaryToken = Return-PrimaryToken -TargetPID $ProcessList[$i].Id
		if ($PrimaryToken) {
			$ProcessTokenArray += $PrimaryToken
		}

		$ThreadTokens = Return-ThreadTokens -TargetPID $ProcessList[$i].Id
		if ($ThreadTokens) {
			$ProcessTokenArray += $ThreadTokens
		}

		for ($j=0;$j -lt $ProcessTokenArray.Length;$j++) {
			# Re-cast token handle Str->Int
			$TokenHandle = [Convert]::ToInt32($(($ProcessTokenArray[$j]).Split("-")[0]))
			if ($Mode -eq "Detailed") {
				Return-TokenInformation -hToken $TokenHandle -TID ($ProcessTokenArray[$j]).Split("-")[1] -ProcID $ProcessList[$i].Id
			} elseif ($Mode -eq "Brief" -Or $Mode -eq "Statistics") {
				$ResultObject += Return-TokenInformation -hToken $TokenHandle -TID ($ProcessTokenArray[$j]).Split("-")[1] -ProcID $ProcessList[$i].Id
			}
		}
	}

	if ($Mode -eq "Brief") {
		$ResultObject |Select-Object Process,PID,TID,Elevated,ImpersonationType,User| Format-Table -AutoSize
	}

	# Revert to own token
	$CallResult = [TokenEnum]::RevertToSelf()
}
