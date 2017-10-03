Param($adTenant, $AADSyncURL, $user, $pass)

#used for error logging
$ScriptName = "ADConnect.ps1"

#Clears errors for error handling that was added at the end.
$Error.Clear()
$api = new-object -comObject "MOM.ScriptAPI"

$SCOMPowerShellKey = "HKLM:\SOFTWARE\Microsoft\System Center Operations Manager\12\Setup\Powershell\V2"
$SCOMModulePath = Join-Path (Get-ItemProperty $SCOMPowerShellKey).InstallDirectory "OperationsManager"

if (!(Get-Module OperationsManager))
{
	Import-module $SCOMModulePath
}

$ADAuthLib= "C:\Program Files (x86)\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\ManagedCache\Microsoft.IdentityModel.Clients.ActiveDirectory.dll" 
$ADAuthLibForms="C:\Program Files (x86)\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\ManagedCache\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
[System.Reflection.Assembly]::LoadFrom($ADAuthLib)
[System.Reflection.Assembly]::LoadFrom($ADAuthLibForms)

$AzurePSClientID = "1950a258-227b-4e31-a9cf-717495945fc2" 
$AzureApiURI = "https://management.azure.com/"
$Authority = "https://login.windows.net/common/$adTenant"
$UserCreds = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential" -ArgumentList @($user,(ConvertTo-SecureString -String $pass -AsPlainText -Force))
$AuthContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $Authority
$AuthResult = $AuthContext.AcquireToken($AzureApiURI,$AzurePSClientID,$UserCreds)

$RequestUri="https://management.azure.com/providers/Microsoft.ADHybridHealthService/services/$AADSyncUrl/servicemembers/?api-version=2014-01-01"
$Rest =Invoke-RestMethod -Uri "$RequestUri" -Headers @{Authorization=$AuthResult.CreateAuthorizationHeader()} -ContentType "application/json" 
$ServiceMemberID = $rest.Value | Select ServiceMemberID -ExpandProperty "ServiceMemberID"

$RequestUri2="https://management.azure.com/providers//Microsoft.ADHybridHealthService/services/$AADSyncUrl/servicemembers/$ServiceMemberID/alerts/?state=Resolved&api-version=2014-01-01"
$RestResolvedAlerts =Invoke-RestMethod -Uri "$RequestUri2" -Headers @{Authorization=$AuthResult.CreateAuthorizationHeader()} -ContentType "application/json" 
$ResolvedValues=$RestResolvedAlerts.value

$RequestUri3="https://management.azure.com/providers//Microsoft.ADHybridHealthService/services/$AADSyncUrl/servicemembers/$ServiceMemberID/alerts/?state=Active&api-version=2014-01-01"
$RestActiveAlerts =Invoke-RestMethod -Uri "$RequestUri3" -Headers @{Authorization=$AuthResult.CreateAuthorizationHeader()} -ContentType "application/json" 
$ActiveAlertValues=$RestActiveAlerts.value

$ResolvedGuids=@()

Foreach ($RValue in $ResolvedValues)
{
	$GUID= $RValue.alertId
	$ResolvedGuids+=$GUID
}

# updated to include all unclosed alerts
$SCOMActiveAlerts= Get-SCOMAlert -Criteria "Name LIKE '%Azure AD Connect Sync - OpsConfig -%' AND ResolutionState <> 255 AND IsMonitorAlert = 0"

$ActiveSCOMAlertGUIDS=@()

Foreach ($Alert in $SCOMActiveAlerts)
{
	$AzureADConnectLength =$alert.Description.Length-1
	$AzIndex = $AzureADConnectLength-37
	$AzSub = $alert.Description.Substring($AzIndex,36)
	$ActiveSCOMAlertGUIDS+=$AzSub

		If ($ResolvedGuids -contains $AzSub -Or $ResolvedGuids -match $AzSub)
        {
			$Alert | Resolve-SCOMAlert -comment "Azure AD Connect has automatically resolved this alert"	
        } 
}

Foreach ($Value in $ActiveAlertValues)
{
	if ($AciveSCOMAlertGUIDS -contains $Value.alertId -Or $ActiveSCOMAlertGUIDS -match $Value.alertId)
    {
		break
    }

    else
    {
		$AlertName = $Value.displayName
		$Scope= $Value.scope
		$NoHtml = $Value.description -replace '<[^>]+>',''
		$Length = $NoHtml.Length-1
		$AlertDescription= $NoHtml.Substring(1,$Length) 
			
			if ($Value.level -contains "Error")
			{
				[int]$EventID= 9952
				[int]$Severity= 1
			}
			if ($Value.level -contains "Warning")
			{
				[int]$EventID = 9953
				[int]$Severity = 2
			}
        
			$WaterMarkGUID= $Value.alertId

        $api.LogScriptEvent("[Azure AD Connect Health Sync] ",$EventID,$Severity,"`n`n[Source: $Scope]`n`n[Description:$AlertDescription]`n`n[GUID: $WaterMarkGUID]")
	}
}
#Logging Errors 
If ($Error.Count -ne 0)
    {
        [int]$EventID= 9951
	[int]$Severity= 1
        $AlertDescription = "Script failure: $scriptname; $error"
	$api.LogScriptEvent("[Azure AD Connect Health Sync] ",$EventID,$Severity,"`n`n[Description:$AlertDescription]")
    }
