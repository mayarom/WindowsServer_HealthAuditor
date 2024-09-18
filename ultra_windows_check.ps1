# Function to log messages with a timestamp
function Log-Message {
    param (
        [string]$message,
        [string]$color = "Green"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $message" -ForegroundColor $color
}

# Function to export to CSV with error handling
function Export-ToCsvSafe {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [array]$InputObject
    )
    try {
        $InputObject | Export-Csv -Path $Path -NoTypeInformation -ErrorAction Stop
        Log-Message "Exported to CSV successfully: $Path"
    } catch {
        Log-Message "Failed to export to CSV at $Path. $_" "Red"
    }
}

# Function to export HTML with styling and error highlighting
function Export-ToHtml {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [array]$InputObject
    )
    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #2e6c80; text-align: center; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .error { background-color: #ffcccc; color: red; }
    </style>
</head>
<body>
"@
    $htmlFooter = @"
</body>
</html>
"@
    try {
        $htmlBody = $InputObject | ConvertTo-Html -Property * -Head $htmlHeader -PostContent $htmlFooter
        Set-Content -Path $Path -Value $htmlBody -ErrorAction Stop
        Log-Message "Exported to HTML successfully: $Path"
    } catch {
        Log-Message "Failed to export to HTML at $Path. $_" "Red"
    }
}

# Function to export user and group information, including local and AD users and groups
function Export-UserAndGroupInfo {
    param (
        [string]$groupsFilePath,
        [string]$groupMembersFilePath
    )
    
    # Collect local groups
    try {
        $localGroups = Get-LocalGroup | Select-Object Name, Description, SID
        Export-ToHtml -Path $groupsFilePath -InputObject $localGroups
    } catch {
        Log-Message "Failed to retrieve local groups. $_" "Red"
    }

    # Collect AD groups if applicable
    if (Get-Command -Name Get-ADGroup -ErrorAction SilentlyContinue) {
        try {
            $adGroups = Get-ADGroup -Filter * | Select-Object Name, Description, SID
            if ($adGroups.Count -gt 0) {
                $adGroupsHtml = ConvertTo-Html -InputObject $adGroups -Fragment
                $adGroupsContent = "<h2>Active Directory Groups</h2>" + $adGroupsHtml
                Add-Content -Path $groupsFilePath -Value $adGroupsContent
            }
        } catch {
            Log-Message "No Active Directory groups found or unable to connect to AD. $_" "Red"
        }
    } else {
        Log-Message "Active Directory commands not available." "Yellow"
    }

    # Export group members for local groups
    $groupMembersContent = ""
    Get-LocalGroup | ForEach-Object {
        $groupName = $_.Name
        $groupMembersContent += "<h2>Group: $groupName</h2><table><tr><th>Members</th></tr>"
        try {
            $groupMembers = Get-LocalGroupMember -Group $_ | ForEach-Object { $_.Name }
            if ($groupMembers.Count -gt 0) {
                $groupMembers | ForEach-Object {
                    $groupMembersContent += "<tr><td>$_</td></tr>"
                }
            } else {
                $groupMembersContent += "<tr><td>No users in this group</td></tr>"
            }
        } catch {
            Log-Message "Failed to retrieve members for group $groupName. $_" "Red"
            $groupMembersContent += "<tr><td>Error retrieving group members</td></tr>"
        }
        $groupMembersContent += "</table><br>"
    }

    $groupMembersHtml = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
    </style>
</head>
<body>
$groupMembersContent
</body>
</html>
"@
    Set-Content -Path $groupMembersFilePath -Value $groupMembersHtml
    Log-Message "Group members list exported: $groupMembersFilePath"
}

# Function to export SQL Server security settings if SQL Server is installed
function Export-SQLSecuritySettings {
    param (
        [string]$sqlSecurityFilePath
    )
    
    if (Get-Command -Name Invoke-Sqlcmd -ErrorAction SilentlyContinue) {
        try {
            $sqlInstances = Get-Service | Where-Object { $_.DisplayName -like "SQL Server*" } | Select-Object -ExpandProperty DisplayName
            if ($sqlInstances.Count -gt 0) {
                $sqlSecurityHtmlContent = "<h2>SQL Server Security Settings</h2>"
                foreach ($instance in $sqlInstances) {
                    $instanceName = $instance -replace "SQL Server ", ""
                    $serverInstance = ".\$instanceName"
                    $loginPolicies = Invoke-Sqlcmd -Query "SELECT name, is_policy_checked, is_expiration_checked, is_disabled FROM sys.sql_logins" -ServerInstance $serverInstance
                    $configurations = Invoke-Sqlcmd -Query "EXEC sp_configure" -ServerInstance $serverInstance
                    $sqlSecurityHtmlContent += "<h3>Instance: $instanceName</h3>"
                    $sqlSecurityHtmlContent += "<h4>Login Policies</h4>"
                    $sqlSecurityHtmlContent += ConvertTo-Html -InputObject $loginPolicies -Fragment
                    $sqlSecurityHtmlContent += "<h4>Server Configurations</h4>"
                    $sqlSecurityHtmlContent += ConvertTo-Html -InputObject $configurations -Fragment
                }
                $sqlSecurityHtml = "<html>...</html>" # Add HTML export logic here
                Set-Content -Path $sqlSecurityFilePath -Value $sqlSecurityHtml
                Log-Message "SQL Server security settings exported: $sqlSecurityFilePath"
            } else {
                Log-Message "No SQL Server instances found on this server." "Yellow"
            }
        } catch {
            Log-Message "Failed to export SQL Server security settings. $_" "Red"
        }
    } else {
        Log-Message "SQL Server commands not available." "Yellow"
    }
}

# Function to export AD password policy
function Export-ADPasswordPolicy {
    param (
        [string]$policyFilePath
    )
    
    if (Get-Command -Name Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue) {
        try {
            $passwordPolicy = Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, PasswordHistoryCount, MaxPasswordAge, MinPasswordAge, LockoutThreshold, LockoutDuration, LockoutObservationWindow, ComplexityEnabled, ReversibleEncryptionEnabled
            $policyHtmlContent = ConvertTo-Html -InputObject $passwordPolicy -Fragment
            $policyHtml = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
    </style>
</head>
<body>
<h2>Active Directory Password Policy</h2>
$policyHtmlContent
</body>
</html>
"@
            Set-Content -Path $policyFilePath -Value $policyHtml
            Log-Message "Active Directory password policy exported: $policyFilePath"
        } catch {
            Log-Message "Failed to export AD password policy. $_" "Red"
        }
    } else {
        Log-Message "Active Directory commands not available." "Yellow"
    }
}

# Try to export IIS security configuration to XML and HTML files
Log-Message "Exporting IIS security configuration..."
if (Get-Command -Name Get-WebConfiguration -ErrorAction SilentlyContinue) {
    try {
        # Load WebAdministration module if not already loaded
        if (-not (Get-Module -ListAvailable -Name "WebAdministration")) {
            Import-Module WebAdministration
        }
        # Extract various security-related settings
        $securityConfig = @(
            @{Name = "AnonymousAuthentication"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/authentication/anonymousAuthentication" -name "enabled")},
            @{Name = "RequestFiltering"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowUnlisted")}
        )
        $securityHtml = "<html>...</html>"  # Add HTML export logic here
        Set-Content -Path "$folderPath\IIS_SecurityConfig_$serverName.html" -Value $securityHtml
        Log-Message "IIS security configuration exported."
    } catch {
        Log-Message "Failed to retrieve IIS security configuration. $_" "Red"
    }
} else {
    Log-Message "IIS not installed." "Yellow"
}

# Microsoft Defender settings check
Log-Message "Checking Microsoft Defender settings..."
if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
    try {
        $defenderSettings = Get-MpPreference | ConvertTo-Html -Fragment
        $defenderHtml = "<html>...</html>"  # Add HTML export logic here
        Set-Content -Path $defenderConfigFilePath -Value $defenderHtml
        Log-Message "Microsoft Defender settings exported."
    } catch {
        Log-Message "Failed to export Microsoft Defender settings. $_" "Red"
    }
} else {
    Log-Message "Microsoft Defender commands not available." "Yellow"
}

# Continue exporting other data in similar fashion...
