################################### GET-HELP #############################################
<#
.SYNOPSIS
 	This script will prompt you for a user ID, create a safe for that user then premession
	that user on the safe with full admin rights then create the credential in the safe.
 
.EXAMPLE
 	.\New-EPVSafe.ps1 -bulk $false
	.\New-EPVSafe.ps1 -bulk $true -csvPath "C:\temp\onboard.csv"
 
.INPUTS  
	None via command line
	
.OUTPUTS
	None
	
.NOTES
	AUTHOR:  
	Randy Brown

	VERSION HISTORY:
	1.0 12/05/2018 - Initial release
	1.1 12/19/2018 - Added fucntion for bulk import
	1.2 01/18/2019 - Added check for existing safe before creation
	1.3 01/22/2019 - Added checks for existing members of safe
	1.4 04/17/2020 - Made the script more generic for adding a safe only
#>
##########################################################################################

param (
	[Parameter(Mandatory=$true)][bool]$bulk,
	[string]$csvPath
)

######################## IMPORT MODULES/ASSEMBLY LOADING #################################

Import-Module ActiveDirectory

######################### GLOBAL VARIABLE DECLARATIONS ###################################

$baseURI = "https://components.cyberarkdemo.com"
$ldapDIR = "cyberarkdemo.com"
$adminGroup = "Vault Admins"

$errorOccured = $false

########################## START FUNCTIONS ###############################################

Function EPV-Login($user, $pass) {
	
	$data = @{
		username=$user
		password=$pass
		useRadiusAuthentication=$false
	}
	
	$loginData = $data | ConvertTo-Json
		
	$ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logon" -Method POST -Body $loginData -ContentType 'application/json'
	
	return $ret
}

Function EPV-Logoff {
	Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff" -Method POST -Headers $header -ContentType 'application/json'
}

Function EPV-GetAPIAccount {
	$ret = Invoke-RestMethod -Uri "$baseURI/AIMWebService/api/Accounts?AppID=UnlockUser&Safe=Unlock Users&Object=UserUnlock" -Method GET -ContentType 'application/json'

	return $ret
}

Function EPV-CreateSafe($safeName, $description) {
	$existingSafe = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/PIMServices.svc/Safes?query=$safeName" -Method GET -Headers $header -ContentType 'application/json'
	
	If (!($existingSafe.SearchSafesResult)) {
		Write-Host "Safe $safeName does not exist creating it..." -ForegroundColor Yellow
		
		$data = @{
			safe = @{
				SafeName=$safeName
				Description=$description
				OLACEnabled=$false
				ManagingCPM="PasswordManager"
				NumberOfVersionsRetention=5
			}
		}
		
		$data = $data | ConvertTo-Json

		$ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/PIMServices.svc/Safes" -Method POST -Body $data -Headers $header -ContentType 'application/json'
		
		If ($ret) {
			Write-Host "Safe $safeName was created..." -ForegroundColor Green
		} Else {
			Write-Host "Safe $safeName was not created..." -ForegroundColor Red
		}
	} Else {
		Write-Host "Safe $safeName exists skipping creation..." -ForegroundColor Yellow
	}
}

Function EPV-AddSafeMember($owner, $permsType) {
	$userExists = $false
	
	$existingUser = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/PIMServices.svc/Safes/$safeToCreate/Members" -Method GET -Headers $header -ContentType 'application/json'
	
	Write-Host "Parsing safe members..."
	ForEach ($user in $existingUser.members.UserName) {
		If ($user -like $owner) {
			Write-Host "User $owner is already a member..." -ForegroundColor Yellow
			$userExists = $true
		}
	}
	
	If (!($userExists)) {
		Write-Host "Adding $owner as member of $safeToCreate..."
		Write-Verbose "Owner: $owner"
		$body = (Get-SafePermissions $owner $permsType)

		Try {
			$ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/PIMServices.svc/Safes/$safeToCreate/Members" -Method POST -Body $body -Headers $header -ContentType 'application/json'
			Write-Host "User $owner was added..." -ForegroundColor Green
		} Catch {
			Write-Host "Something went wrong, $owner was not added as a member of $safeToCreate..." -ForegroundColor Red
			Write-Host $_.Exception.Message -ForegroundColor Red
			Write-Host $_ -ForegroundColor Red
		}
	}
}

Function Get-SafePermissions($owner, $type) {
	Switch ($type.ToLower()) {
		"all" { $PERMISSIONS = @{
				member = @{
					MemberName="$owner"
					SearchIn="$ldapDIR"
					MembershipExpirationDate=""
					Permissions = @(
						@{Key="UseAccounts"
						Value=$true}
						@{Key="RetrieveAccounts"
						Value=$true}
						@{Key="ListAccounts"
						Value=$true}
						@{Key="AddAccounts"
						Value=$true}
						@{Key="UpdateAccountContent"
						Value=$true}
						@{Key="UpdateAccountProperties"
						Value=$true}
						@{Key="InitiateCPMAccountManagementOperations"
						Value=$true}
						@{Key="SpecifyNextAccountContent"
						Value=$true}
						@{Key="RenameAccounts"
						Value=$true}
						@{Key="DeleteAccounts"
						Value=$true}
						@{Key="UnlockAccounts"
						Value=$true}
						@{Key="ManageSafe"
						Value=$true}
						@{Key="ManageSafeMembers"
						Value=$true}
						@{Key="BackupSafe"
						Value=$true}
						@{Key="ViewAuditLog"
						Value=$true}
						@{Key="ViewSafeMembers"
						Value=$true}
						@{Key="RequestsAuthorizationLevel"
						Value=0}
						@{Key="AccessWithoutConfirmation"
						Value=$true}
						@{Key="CreateFolders"
						Value=$true}
						@{Key="DeleteFolders"
						Value=$true}
						@{Key="MoveAccountsAndFolders"
						Value=$true}
					)
				}
			}
			$PERMISSIONS = $PERMISSIONS | ConvertTo-Json -Depth 3
			return $PERMISSIONS; break }
		"admin" { $PERMISSIONS = @{
				member = @{
					MemberName="$owner"
					SearchIn="Vault"
					MembershipExpirationDate=""
					Permissions = @(
						@{Key="UseAccounts"
						Value=$false}
						@{Key="RetrieveAccounts"
						Value=$false}
						@{Key="ListAccounts"
						Value=$true}
						@{Key="AddAccounts"
						Value=$true}
						@{Key="UpdateAccountContent"
						Value=$false}
						@{Key="UpdateAccountProperties"
						Value=$true}
						@{Key="InitiateCPMAccountManagementOperations"
						Value=$true}
						@{Key="SpecifyNextAccountContent"
						Value=$false}
						@{Key="RenameAccounts"
						Value=$false}
						@{Key="DeleteAccounts"
						Value=$true}
						@{Key="UnlockAccounts"
						Value=$true}
						@{Key="ManageSafe"
						Value=$true}
						@{Key="ManageSafeMembers"
						Value=$true}
						@{Key="BackupSafe"
						Value=$true}
						@{Key="ViewAuditLog"
						Value=$true}
						@{Key="ViewSafeMembers"
						Value=$true}
						@{Key="RequestsAuthorizationLevel"
						Value=0}
						@{Key="AccessWithoutConfirmation"
						Value=$false}
						@{Key="CreateFolders"
						Value=$true}
						@{Key="DeleteFolders"
						Value=$true}
						@{Key="MoveAccountsAndFolders"
						Value=$true}
					)
				}
			}
			$PERMISSIONS = $PERMISSIONS | ConvertTo-Json -Depth 3
			return $PERMISSIONS; break }
	}
}

Function Remove-SafeMemeber($safe, $safeMember, $existingUser) {
	$userExists = $false
	
	Write-Host "Parsing safe members..." -NoNewline
	ForEach ($user in $existingUser.members.UserName) {
		If ($user.ToLower() -like $safeMember.ToLower()) {
			$userExists = $true
			break
		}			
	}

	If (!($safeMember -eq $safe) -and $userExists) {
		Try {
			Write-Host "Done!" -ForegroundColor Green
			Write-Host "Removing $safeMember from $safe..." -NoNewline
			
			Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/PIMServices.svc/Safes/$safe/Members/$safeMember" -Method Delete -ContentType 'application/json' -Headers $header | Out-Null
			
			Write-Host "Success!" -ForegroundColor Green
		} Catch {
			ErrorHandler "Something went wrong, $safeMember was not removed from $safe." $_.Exception.Message $_ $true
		}
	} Else {
		Write-Host "$safeMember not a member of $safe" -ForegroundColor Yellow
	}
}

Function Get-SafeMembers($safeToCreate) {
	Try {
		Write-Host "Getting members of $safeToCreate..." -NoNewline
		$existingUser = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/PIMServices.svc/Safes/$safeToCreate/Members" -Method Get -Headers $header -ContentType 'application/json'
		Write-Host "Success!" -ForegroundColor Green
		return $existingUser
	} Catch {
		ErrorHandler "Something went wrong, unable to get memebrs of $safeToCreate..." $_.Exception.Message $_ $true
	}
}

Function ErrorHandler($message, $exceptionMessage, $fullMessage, $logoff) {
	Write-Host $message -ForegroundColor Red
	Write-Host "Exception Message:"
	Write-Host $exceptionMessage -ForegroundColor Red
	Write-Host "Full Error Message:"
	Write-Host $fullMessage -ForegroundColor Red
	Write-Host "Stopping script" -ForegroundColor Yellow
	
	If ($logoff) {
		EPV-Logoff
	}
	Exit 1
}

Function MAIN($mortal, $safeName, $privAccount, $safeDescription, $user) {
	EPV-CreateSafe $safeName $safeDescription
	$existingUsers = Get-SafeMembers $safeName
	EPV-AddSafeMember $mortal "all"	
	EPV-AddSafeMember $adminGroup "admin"	
	Remove-SafeMemeber $safeName $user $existingUsers

	Write-Host "Script complete!"
}

########################## END FUNCTIONS #################################################

########################## MAIN SCRIPT BLOCK #############################################

#$cred = EPV-GetAPIAccount
$user = "Safe_Creator"
$login = EPV-Login $user Cyberark1
$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$header.Add("Authorization", $login.CyberArkLogonResult)

If ($bulk) {
	$csvObject = (Import-Csv $csvPath)
	
	ForEach ($item in $csvObject) {
		$userID = $item.Name
		$safeToCreate = $item."Safe Name"
		$ADDetails = (Get-ADUser $userID)
		$description = $ADDetails.GivenName + " " + $ADDetails.Surname + ", " + $ADDetails.SamAccountName
		
		MAIN $userID $safeToCreate $privAcct $description $user
	}
} Else {
	$userID = Read-Host "What is the samAccountName of the user that needs the safe"
	$safeToCreate = Read-Host "What is the name of the safe you want to create"
	$ADDetails = (Get-ADUser $userID)
	$description = $ADDetails.GivenName + " " + $ADDetails.Surname + ", " + $ADDetails.SamAccountName
	
	MAIN $userID $safeToCreate $privAcct $description $user
}

EPV-Logoff

########################### END SCRIPT ###################################################
