# הגדרת משתנים גלובליים
$serverName = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$folderPath = Join-Path $desktopPath "SecurityAudit_$timestamp"
$groupsFilePath = Join-Path $folderPath "Groups_$serverName.html"
$groupMembersFilePath = Join-Path $folderPath "GroupMembers_$serverName.html"
$sqlSecurityFilePath = Join-Path $folderPath "SQLSecurity_$serverName.html"
$policyFilePath = Join-Path $folderPath "ADPolicy_$serverName.html"
$defenderConfigFilePath = Join-Path $folderPath "DefenderConfig_$serverName.html"
$iisConfigFilePath = Join-Path $folderPath "IIS_SecurityConfig_$serverName.html"

# יצירת תיקיית הייצוא
if (-not (Test-Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath | Out-Null
    Write-Host "Created audit directory at: $folderPath"
}

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
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
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

# Function to export user and group information
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

    # Collect AD groups if available
    if (Get-Command -Name Get-ADGroup -ErrorAction SilentlyContinue) {
        try {
            $adGroups = Get-ADGroup -Filter * | Select-Object Name, Description, SID
            if ($adGroups.Count -gt 0) {
                $adGroupsHtml = ConvertTo-Html -InputObject $adGroups -Fragment
                $adGroupsContent = "<h2>Active Directory Groups</h2>" + $adGroupsHtml
                Add-Content -Path $groupsFilePath -Value $adGroupsContent
            }
        } catch {
            Log-Message "No Active Directory groups found or unable to connect to AD. $_" "Yellow"
        }
    } else {
        Log-Message "Active Directory commands not available." "Yellow"
    }

    # Export group members
    $groupMembersContent = "<h2>Group Members</h2>"
    Get-LocalGroup | ForEach-Object {
        $groupName = $_.Name
        $groupMembersContent += "<h3>Group: $groupName</h3><table><tr><th>Member Name</th><th>Account Type</th></tr>"
        try {
            $groupMembers = Get-LocalGroupMember -Group $_ 
            if ($groupMembers.Count -gt 0) {
                $groupMembers | ForEach-Object {
                    $groupMembersContent += "<tr><td>$($_.Name)</td><td>$($_.ObjectClass)</td></tr>"
                }
            } else {
                $groupMembersContent += "<tr><td colspan='2'>No users in this group</td></tr>"
            }
        } catch {
            Log-Message "Failed to retrieve members for group $groupName. $_" "Red"
            $groupMembersContent += "<tr><td colspan='2' class='error'>Error retrieving group members</td></tr>"
        }
        $groupMembersContent += "</table><br>"
    }

    $groupMembersHtml = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2, h3 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .error { background-color: #ffcccc; color: red; }
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

# Function to export SQL Server security settings
function Export-SQLSecuritySettings {
    param (
        [string]$sqlSecurityFilePath
    )
    
    if (Get-Command -Name Invoke-Sqlcmd -ErrorAction SilentlyContinue) {
        try {
            $sqlInstances = Get-Service | Where-Object { $_.DisplayName -like "SQL Server (*)" } | 
                           Select-Object -ExpandProperty Name
            
            if ($sqlInstances.Count -gt 0) {
                $sqlSecurityHtmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2, h3, h4 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .error { background-color: #ffcccc; color: red; }
    </style>
</head>
<body>
<h2>SQL Server Security Settings</h2>
"@
                foreach ($instance in $sqlInstances) {
                    $instanceName = $instance -replace "MSSQL\$"
                    $serverInstance = ".\$instanceName"
                    
                    try {
                        # Get SQL login policies
                        $loginPolicies = Invoke-Sqlcmd -Query @"
                            SELECT name, 
                                   is_policy_checked,
                                   is_expiration_checked,
                                   is_disabled,
                                   type_desc as login_type
                            FROM sys.sql_logins
"@ -ServerInstance $serverInstance

                        # Get SQL security configurations
                        $configurations = Invoke-Sqlcmd -Query @"
                            SELECT name, 
                                   CAST(value as int) as configured_value,
                                   CAST(value_in_use as int) as value_in_use
                            FROM sys.configurations
                            WHERE name IN (
                                'clr enabled',
                                'cross db ownership chaining',
                                'remote access',
                                'remote admin connections',
                                'xp_cmdshell'
                            )
"@ -ServerInstance $serverInstance

                        $sqlSecurityHtmlContent += "<h3>Instance: $instanceName</h3>"
                        $sqlSecurityHtmlContent += "<h4>Login Policies</h4>"
                        $sqlSecurityHtmlContent += $loginPolicies | ConvertTo-Html -Fragment
                        $sqlSecurityHtmlContent += "<h4>Security-Critical Configurations</h4>"
                        $sqlSecurityHtmlContent += $configurations | ConvertTo-Html -Fragment
                    }
                    catch {
                        $sqlSecurityHtmlContent += "<p class='error'>Error accessing instance $instanceName: $($_.Exception.Message)</p>"
                    }
                }
                
                $sqlSecurityHtmlContent += "</body></html>"
                Set-Content -Path $sqlSecurityFilePath -Value $sqlSecurityHtmlContent
                Log-Message "SQL Server security settings exported: $sqlSecurityFilePath"
            }
            else {
                Log-Message "No SQL Server instances found on this server." "Yellow"
            }
        }
        catch {
            Log-Message "Failed to export SQL Server security settings. $_" "Red"
        }
    }
    else {
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
            $passwordPolicy = Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, 
                                                                             PasswordHistoryCount, 
                                                                             MaxPasswordAge, 
                                                                             MinPasswordAge, 
                                                                             LockoutThreshold, 
                                                                             LockoutDuration, 
                                                                             LockoutObservationWindow, 
                                                                             ComplexityEnabled, 
                                                                             ReversibleEncryptionEnabled
            $policyHtmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
    </style>
</head>
<body>
<h2>Active Directory Password Policy</h2>
$(ConvertTo-Html -InputObject $passwordPolicy -Fragment)
</body>
</html>
"@
            Set-Content -Path $policyFilePath -Value $policyHtmlContent
            Log-Message "Active Directory password policy exported: $policyFilePath"
        } catch {
            Log-Message "Failed to export AD password policy. $_" "Red"
        }
    } else {
        Log-Message "Active Directory commands not available." "Yellow"
    }
}

# Check and export IIS security configuration
Log-Message "Checking IIS security configuration..."
if (Get-Command -Name Get-WebConfiguration -ErrorAction SilentlyContinue) {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        
        $securityConfig = @(
            # Authentication Settings
            @{Category = "Authentication"; Setting = "Anonymous Authentication"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/anonymousAuthentication" -name "enabled")}
            @{Category = "Authentication"; Setting = "Windows Authentication"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/windowsAuthentication" -name "enabled")}
            @{Category = "Authentication"; Setting = "Basic Authentication"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/authentication/basicAuthentication" -name "enabled")}
            
            # Request Filtering
            @{Category = "Request Filtering"; Setting = "Allow Unlisted File Extensions"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering" -name "allowUnlisted")}
            @{Category = "Request Filtering"; Setting = "Max URL Length"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering" -name "maxUrl")}
            @{Category = "Request Filtering"; Setting = "Max Query String Length"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering" -name "maxQueryString")}
            
            # SSL Settings
            @{Category = "SSL Settings"; Setting = "Require SSL"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/access" -name "sslFlags")}
        )
        
        $iisHtml = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
    </style>
</head>
<body>
<h2>IIS Security Configuration</h2>
$(ConvertTo-Html -InputObject $securityConfig -Fragment)
</body>
</html>
"@
        Set-Content -Path $iisConfigFilePath -Value $iisHtml
        Log-Message "IIS security configuration exported successfully."
    }
    catch {
        Log-Message "Failed to retrieve IIS security configuration. $_" "Red"
    }
}
else {
    Log-Message "IIS not installed." "Yellow"
}

# Microsoft Defender settings check
Log-Message "Checking Microsoft Defender settings..."
if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
    try {
        $defenderSettings = Get-MpPreference | Select-Object @{Name='Setting';Expression={$_.PSObject.Properties.Name}}, 
                                                           @{Name='Value';Expression={$_.PSObject.Properties.Value}} |
                                              Where-Object {$_.Value -ne $null}
        
        $defenderHtml = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
    </style>
</head>
<body>
<h2>Microsoft Defender Settings</h2>
$(ConvertTo-Html -InputObject $defenderSettings -Fragment)
</body>
</html>
"@
        Set-Content -Path $defenderConfigFilePath -Value $defenderHtml
        Log-Message "Microsoft Defender settings exported successfully."
    }
    catch {
        Log-Message "Failed to export Microsoft Defender settings. $_" "Red"
    }
}
else {
    Log-Message "Microsoft Defender commands not available." "Yellow"
}

# Generate main report
$mainReportPath = Join-Path $folderPath "SecurityAudit_Summary.html"
$mainReportContent = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #2e6c80; }
        .report-section { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
    </style>
</head>
<body>
<h1>Security Audit Summary Report</h1>
<div class="report-section">
    <h2>Server Information</h2>
    <p>Server Name: $serverName</p>
    <p>Audit Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
</div>
<div class="report-section">
    <h2>Generated Reports</h2>
    <ul>
"@

# Add links to generated reports
$reports = Get-ChildItem -Path $folderPath -Filter "*.html" | Where-Object { $_.Name -ne "SecurityAudit_Summary.html" }
foreach ($report in $reports) {
    $mainReportContent += "<li><a href=`"$($report.Name)`">$($report.Name)</a></li>`n"
}

$mainReportContent += @"
    </ul>
</div>
</body>
</html>
"@

Set-Content -Path $mainReportPath -Value $mainReportContent
Log-Message "Main summary report generated: $mainReportPath"

# הפעלת כל הפונקציות
try {
    Log-Message "Starting security audit..."
    
    Export-UserAndGroupInfo -groupsFilePath $groupsFilePath -groupMembersFilePath $groupMembersFilePath
    Export-SQLSecuritySettings -sqlSecurityFilePath $sqlSecurityFilePath
    Export-ADPasswordPolicy -policyFilePath $policyFilePath
    
    Log-Message "Security audit completed successfully."
    Log-Message "All reports have been saved to: $folderPath"
    
    # פתיחת תיקיית הדוחות
    Start-Process explorer.exe -ArgumentList $folderPath
}
catch {
    Log-Message "An error occurred during the audit process: $_" "Red"
}
