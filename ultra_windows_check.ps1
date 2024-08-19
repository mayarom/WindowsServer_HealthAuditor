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

# Function to check for insecure settings and flag them
function Check-InsecureSettings {
    param (
        [array]$Settings
    )
    $flaggedSettings = @()
    foreach ($setting in $Settings) {
        if ($setting.Name -eq "AnonymousAuthentication" -and $setting.Value -eq $true) {
            $flaggedSettings += "<tr class='error'><td>$($setting.Name)</td><td>Anonymous Authentication is enabled (Insecure)</td></tr>"
        } elseif ($setting.Name -eq "RequestFiltering" -and $setting.Value -eq $false) {
            $flaggedSettings += "<tr class='error'><td>$($setting.Name)</td><td>Request Filtering is disabled (Insecure)</td></tr>"
        } else {
            $flaggedSettings += "<tr><td>$($setting.Name)</td><td>$($setting.Value)</td></tr>"
        }
    }
    return $flaggedSettings
}

# Function to check detailed Microsoft Defender settings
function Check-DefenderSettings {
    $defenderStatus = Get-MpComputerStatus
    $defenderPreferences = Get-MpPreference

    $defenderSettings = @(
        @{Name = "RealTimeProtectionEnabled"; Value = !$defenderPreferences.DisableRealtimeMonitoring; Issue = "Real-Time Protection is not enabled"},
        @{Name = "CloudProtectionEnabled"; Value = $defenderPreferences.MAPSReporting -eq "2"; Issue = "Cloud Protection is not enabled"},
        @{Name = "VirusDefinitionsUpToDate"; Value = $defenderStatus.AntivirusSignatureLastUpdated -gt (Get-Date).AddDays(-7); Issue = "Virus definitions are not up-to-date"},
        @{Name = "TamperProtectionEnabled"; Value = $defenderPreferences.EnableControlledFolderAccess -eq "Enabled"; Issue = "Tamper Protection is not enabled"},
        @{Name = "PuaProtectionEnabled"; Value = $defenderPreferences.PUAProtection -eq "1"; Issue = "PUA (Potentially Unwanted Application) Protection is not enabled"},
        @{Name = "BehaviorMonitoringEnabled"; Value = !$defenderPreferences.DisableBehaviorMonitoring; Issue = "Behavior Monitoring is not enabled"},
        @{Name = "ScriptScanningEnabled"; Value = !$defenderPreferences.DisableScriptScanning; Issue = "Script Scanning is not enabled"},
        @{Name = "NetworkProtectionEnabled"; Value = $defenderPreferences.ExploitProtectionNetworkProtection -eq "1"; Issue = "Network Protection is not enabled"},
        @{Name = "RansomwareProtectionEnabled"; Value = $defenderPreferences.EnableControlledFolderAccess -eq "Enabled"; Issue = "Ransomware Protection (Controlled Folder Access) is not enabled"},
        @{Name = "SecurityIntelligenceVersion"; Value = $defenderStatus.AntivirusSignatureVersion; Issue = "Security intelligence definitions are out of date"},
        @{Name = "FullScanRequired"; Value = !$defenderStatus.FullScanRequired; Issue = "A full scan is required"},
        @{Name = "FullScanOverdue"; Value = !$defenderStatus.FullScanOverdue; Issue = "Full scan is overdue"},
        @{Name = "QuickScanOverdue"; Value = !$defenderStatus.QuickScanOverdue; Issue = "Quick scan is overdue"},
        @{Name = "LastQuickScanDate"; Value = $defenderStatus.LastQuickScanStartTime; Issue = "No recent quick scan found"},
        @{Name = "LastFullScanDate"; Value = $defenderStatus.LastFullScanStartTime; Issue = "No recent full scan found"},
        @{Name = "AntivirusEnabled"; Value = $defenderStatus.AntivirusEnabled; Issue = "Antivirus protection is not enabled"},
        @{Name = "RealTimeProtectionStatus"; Value = $defenderStatus.RealTimeProtectionEnabled; Issue = "Real-Time Protection is not active"},
        @{Name = "FirewallEnabled"; Value = $defenderStatus.FirewallEnabled; Issue = "Firewall is not enabled"},
        @{Name = "ExploitProtectionEnabled"; Value = $defenderPreferences.ExploitProtectionEnabled; Issue = "Exploit Protection is not enabled"},
        @{Name = "ControlledFolderAccess"; Value = $defenderPreferences.EnableControlledFolderAccess; Issue = "Controlled Folder Access is not enabled"}
    )

    $flaggedSettings = @()
    foreach ($setting in $defenderSettings) {
        if ($setting.Value -eq $false) {
            $flaggedSettings += "<tr class='error'><td>$($setting.Name)</td><td>$($setting.Issue)</td></tr>"
        } elseif ($setting.Name -eq "FullScanOverdue" -and $setting.Value -eq $true) {
            $flaggedSettings += "<tr class='error'><td>$($setting.Name)</td><td>Full scan is overdue</td></tr>"
        } elseif ($setting.Name -eq "QuickScanOverdue" -and $setting.Value -eq $true) {
            $flaggedSettings += "<tr class='error'><td>$($setting.Name)</td><td>Quick scan is overdue</td></tr>"
        } else {
            $flaggedSettings += "<tr><td>$($setting.Name)</td><td>Enabled/Up-to-date</td></tr>"
        }
    }
    return $flaggedSettings
}

# Function to export open ports to HTML
function Export-OpenPortsToHtml {
    param (
        [string]$Path,
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
    </style>
</head>
<body>
<h2>Open Ports Report</h2>
<table>
    <tr>
        <th>Local Address</th>
        <th>Local Port</th>
        <th>Owning Process</th>
    </tr>
"@

    $htmlBody = ""
    foreach ($port in $InputObject) {
        $htmlBody += "<tr><td>$($port.LocalAddress)</td><td>$($port.LocalPort)</td><td>$($port.OwningProcess)</td></tr>"
    }

    $htmlFooter = @"
</table>
</body>
</html>
"@

    try {
        Set-Content -Path $Path -Value ($htmlHeader + $htmlBody + $htmlFooter)
        Log-Message "Open ports list exported: $Path"
    } catch {
        Log-Message "Failed to export open ports list to HTML. $_" "Red"
    }
}

# Function to export user and group information, including local and AD users
function Export-UserAndGroupInfo {
    param (
        [string]$usersFilePath,
        [string]$groupsFilePath,
        [string]$groupMembersFilePath
    )
    
    $localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordChangeableDate, PasswordExpires, UserMayChangePassword
    $adUsers = @()
    try {
        $adUsers = Get-ADUser -Filter * -Property DisplayName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordExpired | Select-Object DisplayName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordExpired
    } catch {
        Log-Message "No Active Directory users found or unable to connect to AD. $_" "Red"
    }

    $usersHtmlContent = "<h2>Local Users</h2>"
    $usersHtmlContent += ConvertTo-Html -InputObject $localUsers -Property Name, Enabled, LastLogon, PasswordChangeableDate, PasswordExpires, UserMayChangePassword -Fragment

    if ($adUsers.Count -gt 0) {
        $usersHtmlContent += "<h2>Active Directory Users</h2>"
        $usersHtmlContent += ConvertTo-Html -InputObject $adUsers -Property DisplayName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordExpired -Fragment
    } else {
        $usersHtmlContent += "<h2>No Active Directory Users Found</h2>"
    }

    Set-Content -Path $usersFilePath -Value $usersHtmlContent
    Log-Message "User information exported: $usersFilePath"

    $groups = Get-LocalGroup | Select-Object Name, Description, SID
    Export-ToHtml -Path $groupsFilePath -InputObject $groups

    $groupMembersContent = ""
    Get-LocalGroup | ForEach-Object {
        $groupName = $_.Name
        $groupMembersContent += "<h2>Group: $groupName</h2><table><tr><th>Members</th></tr>"
        $groupMembers = Get-LocalGroupMember -Group $_ | Select-Object -ExpandProperty Name
        if ($groupMembers) {
            $groupMembers | ForEach-Object {
                $groupMembersContent += "<tr><td>$_</td></tr>"
            }
        } else {
            $groupMembersContent += "<tr><td>No users in this group</td></tr>"
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

# Function to export AD password policy
function Export-ADPasswordPolicy {
    param (
        [string]$policyFilePath
    )
    
    $passwordPolicy = Get-ADDefaultDomainPasswordPolicy | Select-Object -Property MinPasswordLength, PasswordHistoryCount, MaxPasswordAge, MinPasswordAge, LockoutThreshold, LockoutDuration, LockoutObservationWindow, ComplexityEnabled, ReversibleEncryptionEnabled

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
}

# Function to export SQL Server security settings if SQL Server is installed
function Export-SQLSecuritySettings {
    param (
        [string]$sqlSecurityFilePath
    )
    
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
            
            $sqlSecurityHtml = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #2e6c80; text-align: center; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
    </style>
</head>
<body>
$sqlSecurityHtmlContent
</body>
</html>
"@
            Set-Content -Path $sqlSecurityFilePath -Value $sqlSecurityHtml
            Log-Message "SQL Server security settings exported: $sqlSecurityFilePath"
        } else {
            Log-Message "No SQL Server instances found on this server." "Yellow"
        }
    } catch {
        Log-Message "Failed to export SQL Server security settings. $_" "Red"
    }
}

# Function to generate a summary of security issues found
function Generate-SecuritySummary {
    param (
        [string]$summaryFilePath,
        [array]$flaggedSettings
    )
    
    $summaryHtmlContent = "<h2>Security Issues Summary</h2><table><tr><th>Setting</th><th>Issue</th></tr>"
    if ($flaggedSettings.Count -gt 0) {
        $summaryHtmlContent += $flaggedSettings -join "`n"
    } else {
        $summaryHtmlContent += "<tr><td colspan='2'>No security issues found</td></tr>"
    }
    $summaryHtmlContent += "</table>"

    $summaryHtml = @"
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
$summaryHtmlContent
</body>
</html>
"@
    Set-Content -Path $summaryFilePath -Value $summaryHtml
    Log-Message "Security summary exported: $summaryFilePath"
}

# Prompt the user for the customer name and custom server name
$customerName = Read-Host "Please enter the customer name"
$customServerName = Read-Host "Please enter a custom server name"

# Get the current date in the format yyyy-MM-dd
$currentDate = Get-Date -Format "yyyy-MM-dd"

# Get the name of the local server and IP address
$serverName = $env:COMPUTERNAME
$ipAddress = (Test-Connection -ComputerName $serverName -Count 1).IPV4Address.IPAddressToString

# Create a folder on the Desktop named "<customer name>_<IP address>_<custom server name>_<official server name>_<date>"
$folderPath = "$env:USERPROFILE\Desktop\${customerName}_${ipAddress}_${customServerName}_${serverName}_$currentDate"
if (!(Test-Path $folderPath)) {
    try {
        New-Item -ItemType Directory -Path $folderPath -ErrorAction Stop | Out-Null
        Log-Message "Created folder: $folderPath"
    } catch {
        Log-Message "Failed to create folder at $folderPath. $_" "Red"
        exit 1
    }
} else {
    Log-Message "Folder already exists: $folderPath"
}

# Define the file path for all the files
$servicesFilePath = "$folderPath\Services_$serverName.html"
$updatesFilePath = "$folderPath\InstalledUpdates_$serverName.html"
$softwareFilePath = "$folderPath\InstalledSoftware_$serverName.html"
$gpresultFilePath = "$folderPath\GPResult_$serverName.html"
$usersFilePath = "$folderPath\Users_$serverName.html"
$groupsFilePath = "$folderPath\Groups_$serverName.html"
$groupMembersFilePath = "$folderPath\GroupMembers_$serverName.html"
$windowsFeaturesFilePath = "$folderPath\WindowsFeatures_$serverName.html"
$openPortsFilePath = "$folderPath\OpenPorts_$serverName.html"
$sharedFoldersFilePath = "$folderPath\SharedFolders_$serverName.html"
$osVersionFilePath = "$folderPath\OSVersion_$serverName.html"
$iisConfigFilePath = "$folderPath\IISConfig_$serverName.xml"
$noIisConfigFilePath = "$folderPath\NoIISConfig_$serverName.txt"
$defenderConfigFilePath = "$folderPath\DefenderConfig_$serverName.html"
$adPasswordPolicyFilePath = "$folderPath\ADPasswordPolicy_$serverName.html"
$sqlSecurityFilePath = "$folderPath\SQLSecurity_$serverName.html"
$summaryFilePath = "$folderPath\Summary_$serverName.html"

# Get a list of all services on the server and export them to an HTML file
Log-Message "Exporting services list..."
$services = Get-Service | Select-Object Name, DisplayName, Status, StartType
Export-ToHtml -Path $servicesFilePath -InputObject $services

# Get a list of all installed security updates on the server and export them to an HTML file
Log-Message "Exporting installed updates list..."
$updates = Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object HotFixID, InstalledOn
Export-ToHtml -Path $updatesFilePath -InputObject $updates

# Get a list of all installed software on the local server and export them to an HTML file
Log-Message "Exporting installed software list..."
$software = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate
Export-ToHtml -Path $softwareFilePath -InputObject $software

# Get GPResult and save it to the HTML file
Log-Message "Generating GPResult report..."
try {
    gpresult /h $gpresultFilePath
    Log-Message "GPResult report generated: $gpresultFilePath"
} catch {
    Log-Message "Failed to generate GPResult report. $_" "Red"
}

# Export user and group information
Export-UserAndGroupInfo -usersFilePath $usersFilePath -groupsFilePath $groupsFilePath -groupMembersFilePath $groupMembersFilePath

# Check if the server is a domain controller and export AD password policy
if ((Get-WmiObject -Class Win32_ComputerSystem).DomainRole -eq 5) {
    Export-ADPasswordPolicy -policyFilePath $adPasswordPolicyFilePath
}

# Get a list of all listening ports and export them to an HTML file
Log-Message "Exporting listening ports list..."
$openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress, LocalPort, OwningProcess
Export-OpenPortsToHtml -Path $openPortsFilePath -InputObject $openPorts

# Get a list of all shared folders on the server and export them to an HTML file
Log-Message "Exporting shared folders list..."
$sharedFolders = Get-WmiObject -Class Win32_Share | Select-Object Name, Path, Description
Export-ToHtml -Path $sharedFoldersFilePath -InputObject $sharedFolders

# Get the operating system version and export it to an HTML file
Log-Message "Exporting OS version information..."
try {
    $osVersion = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
    $osVersionHtml = @"
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
<h2>Operating System Version</h2>
<table>
    <tr><th>Name</th><td>$($osVersion.Caption)</td></tr>
    <tr><th>Version</th><td>$($osVersion.Version)</td></tr>
    <tr><th>Build Number</th><td>$($osVersion.BuildNumber)</td></tr>
    <tr><th>Architecture</th><td>$($osVersion.OSArchitecture)</td></tr>
</table>
</body>
</html>
"@
    Set-Content -Path $osVersionFilePath -Value $osVersionHtml
    Log-Message "OS version information exported: $osVersionFilePath"
} catch {
    Log-Message "Failed to retrieve OS version information. $_" "Red"
}

# Try to get a list of all installed Windows features using Get-WindowsFeature
Log-Message "Exporting Windows features list..."
$windowsFeaturesContent = ""
try {
    $windowsFeatures = Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"} | Select-Object -ExpandProperty Name
    $commandUsed = "Get-WindowsFeature"
} catch {
    try {
        $windowsFeatures = Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | Select-Object -ExpandProperty FeatureName
        $commandUsed = "Get-WindowsOptionalFeature"
    } catch {
        Log-Message "Failed to retrieve Windows features using both Get-WindowsFeature and Get-WindowsOptionalFeature." "Red"
    }
}

# Add the list of Windows features to the HTML file
if ($windowsFeatures) {
    $windowsFeaturesContent += "<h2>Windows Features</h2><p>The command used to retrieve these features was: $commandUsed</p><table><tr><th>Feature</th></tr>"
    $windowsFeatures | ForEach-Object {
        $windowsFeaturesContent += "<tr><td>$_</td></tr>"
    }
    $windowsFeaturesContent += "</table>"
    $windowsFeaturesHtml = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #2e6c80; text-align: center; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
    </style>
</head>
<body>
$windowsFeaturesContent
</body>
</html>
"@
    Set-Content -Path $windowsFeaturesFilePath -Value $windowsFeaturesHtml
    Log-Message "Windows features list exported: $windowsFeaturesFilePath"
}

# Try to export IIS security configuration to XML and HTML files
Log-Message "Exporting IIS security configuration..."
try {
    # Load WebAdministration module if not already loaded
    if (-not (Get-Module -ListAvailable -Name "WebAdministration")) {
        Import-Module WebAdministration
    }

    # Extract various security-related settings
    $securityConfig = @(
        @{Name = "AnonymousAuthentication"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/authentication/anonymousAuthentication" -name "enabled")},
        @{Name = "RequestFiltering"; Value = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/security/requestFiltering" -name "allowUnlisted")},
        @{Name = "AuthorizationRules"; Value = (Get-WebConfiguration "/system.webServer/security/authorization/*" | Out-String)},
        @{Name = "IPSecurity"; Value = (Get-WebConfiguration "/system.webServer/security/ipSecurity/*" | Out-String)},
        @{Name = "SSLSettings"; Value = (Get-WebConfiguration "/system.webServer/security/access/*" | Out-String)}
    )

    # Check for insecure settings
    $flaggedSettings = Check-InsecureSettings -Settings $securityConfig

    # Create HTML with flagged settings
    $securityHtml = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #2e6c80; text-align: center; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .error { background-color: #ffcccc; color: red; }
    </style>
</head>
<body>
<h2>IIS Security Configuration</h2>
<table>
<tr><th>Setting</th><th>Value</th></tr>
$($flaggedSettings -join "`n")
</table>
</body>
</html>
"@

    # Export the settings to XML and HTML
    $securityConfig | Export-Clixml -Path $iisConfigFilePath
    Set-Content -Path "$folderPath\IIS_SecurityConfig_$serverName.html" -Value $securityHtml

    Log-Message "IIS security configuration exported: $iisConfigFilePath and IIS_SecurityConfig_$serverName.html"
} catch {
    Add-Content -Path $noIisConfigFilePath -Value "Error retrieving IIS security configuration."
    Log-Message "Failed to retrieve IIS security configuration. $_" "Red"
}

# Export Microsoft Defender settings to HTML
Log-Message "Exporting Microsoft Defender settings..."
try {
    $defenderSettings = Check-DefenderSettings
    $defenderHtml = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #2e6c80; text-align: center; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
        th { background-color: #f2f2f2; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:hover { background-color: #f1f1f1; }
        .error { background-color: #ffcccc; color: red; }
    </style>
</head>
<body>
<h2>Microsoft Defender Configuration</h2>
<table>
<tr><th>Setting</th><th>Value</th></tr>
$($defenderSettings -join "`n")
</table>
</body>
</html>
"@
    Set-Content -Path $defenderConfigFilePath -Value $defenderHtml
    Log-Message "Microsoft Defender configuration exported: $defenderConfigFilePath"
} catch {
    Log-Message "Failed to export Microsoft Defender configuration. $_" "Red"
}

# Export SQL Server security settings if SQL Server is installed
Export-SQLSecuritySettings -sqlSecurityFilePath $sqlSecurityFilePath

# Generate a security summary based on flagged settings
Generate-SecuritySummary -summaryFilePath $summaryFilePath -flaggedSettings $flaggedSettings
