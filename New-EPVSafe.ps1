################################### GET-HELP #############################################
<#
.SYNOPSIS
 	This script will prompt you for a user ID, create a safe for that user then premession
	that user on the safe with full admin rights then create the credential in the safe.
 
.EXAMPLE
 	./New-EPVSafe.ps1
 
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
#>
##########################################################################################

param (
	[Parameter(Mandatory=$true)][switch]$bulk,
	[string]$csvPath
)

######################## IMPORT MODULES/ASSEMBLY LOADING #################################

Import-Module ActiveDirectory

######################### GLOBAL VARIABLE DECLARATIONS ###################################

$baseURI = "https://components.cyberarkdemo.com"
$ldapDIR = "ActiveDirectory"
$adminGroup = "CyberarkVaultAdmins"

$address = "cyberarkdemo.com"
$platformId = "WinDomain"

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
	
	return $ret
}

Function EPV-AddSafeMember($owner, $permsType) {
	
	$body = (Get-SafePermissions $owner $permsType)
	
	$ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/PIMServices.svc/Safes/$safeToCreate/Members" -Method POST -Body $body -Headers $header -ContentType 'application/json'
	
	return $ret
}

Function Get-SafePermissions($owner, $type) {
	Switch ($type.ToLower()) {
		"all" { $PERMISSIONS = @{
				member = @{
					MemberName=$owner
					SearchIn=$ldapDIR
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
					MemberName=$owner
					SearchIn=$ldapDIR
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

Function EPV-AddAccount {
	$name = "Operating System-" + $platformId + "-" + $address + "-" + $ownerOfSafe
	
	$data = @{
		account = @{
			safe=$safeToCreate
			platformID=$platformId
			address=$address
			accountName=$name
			password="SuperSecretPassword"
			username=$ownerOfSafe
			disableAutoMgmt=$false		
		}
	}
	
	$data = $data | ConvertTo-Json
	
	$ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/PIMServices.svc/Account" -Method POST -Body $data -Headers $header -ContentType 'application/json'
	
	return $ret
}

Function MAIN($mortal, $privAccount, $safeDescription) {
	$result = EPV-CreateSafe $mortal $safeDescription

	If ($result) {
		Write-Host "Safe created..."
	} Else {
		Write-Host "Safe was not created..." -ForegroundColor Red
		Write-Host "Exiting script..." -ForegroundColor Red
	}

	$result = EPV-AddSafeMember $mortal "all"
	If ($result) {
		Write-Host "Safe member was added..."
	} Else {
		Write-Host "Safe member was not added..." -ForegroundColor Red
		Write-Host "Exiting script..." -ForegroundColor Red
	}

	$result = EPV-AddSafeMember $adminGroup "admin"
	If ($result) {
		Write-Host "Safe member was added..."
	} Else {
		Write-Host "Safe member was not added..." -ForegroundColor Red
		Write-Host "Exiting script..." -ForegroundColor Red
	}

	$result = EPV-AddAccount
	Write-Host "Account was added..."
}

########################## END FUNCTIONS #################################################

########################## MAIN SCRIPT BLOCK #############################################

#$cred = EPV-GetAPIAccount

$login = EPV-Login Safe_Creator Cyberark1
$header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$header.Add("Authorization", $login.CyberArkLogonResult)

If ($bulk) {
	$csvObject = (Import-Csv $csvPath)
	
	ForEach ($item in $csvObject) {
		$mortal = $item.Name
		$priv = $item."Privliged Account"
		$ADDetails = (Get-ADUser $mortal)
		$description = $ADDetails.GivenName + " " + $ADDetails.Surname + ", " + $ADDetails.SamAccountName
		
		MAIN $mortal $priv $description
	}
} Else {
	$safeToCreate = Read-Host "What is the name of the user that needs the safe"
	$priv = Read-Host "What is the privliged account for this user"
	
	$ADDetails = (Get-ADUser $safeToCreate)
	$description = $ADDetails.GivenName + " " + $ADDetails.Surname + ", " + $ADDetails.SamAccountName
	
	MAIN $safeToCreate $priv $description
}

EPV-Logoff

########################### END SCRIPT ###################################################
