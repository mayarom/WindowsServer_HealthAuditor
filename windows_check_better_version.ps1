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
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
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
        @{Name = "RealTimeProtectionEnabled"; Value = !$defenderPreferences.DisableRealtimeMonitoring},
        @{Name = "CloudProtectionEnabled"; Value = $defenderPreferences.MAPSReporting -eq "2"},
        @{Name = "VirusDefinitionsUpToDate"; Value = $defenderStatus.AntivirusSignatureLastUpdated -gt (Get-Date).AddDays(-7)},
        @{Name = "TamperProtectionEnabled"; Value = $defenderPreferences.EnableControlledFolderAccess -eq "Enabled"},
        @{Name = "PuaProtectionEnabled"; Value = $defenderPreferences.PUAProtection -eq "1"},
        @{Name = "BehaviorMonitoringEnabled"; Value = !$defenderPreferences.DisableBehaviorMonitoring},
        @{Name = "ScriptScanningEnabled"; Value = !$defenderPreferences.DisableScriptScanning},
        @{Name = "NetworkProtectionEnabled"; Value = $defenderPreferences.ExploitProtectionNetworkProtection -eq "1"},
        @{Name = "RansomwareProtectionEnabled"; Value = $defenderPreferences.EnableControlledFolderAccess -eq "Enabled"},
        @{Name = "SecurityIntelligenceVersion"; Value = $defenderStatus.AntivirusSignatureVersion},
        @{Name = "FullScanRequired"; Value = $defenderStatus.FullScanRequired},
        @{Name = "FullScanOverdue"; Value = $defenderStatus.FullScanOverdue},
        @{Name = "QuickScanOverdue"; Value = $defenderStatus.QuickScanOverdue},
        @{Name = "LastQuickScanDate"; Value = $defenderStatus.LastQuickScanStartTime},
        @{Name = "LastFullScanDate"; Value = $defenderStatus.LastFullScanStartTime},
        @{Name = "AntivirusEnabled"; Value = $defenderStatus.AntivirusEnabled}
    )

    $flaggedSettings = @()
    foreach ($setting in $defenderSettings) {
        if ($setting.Value -eq $false -or ($setting.Name -eq "FullScanOverdue" -and $setting.Value -eq $true) -or ($setting.Name -eq "QuickScanOverdue" -and $setting.Value -eq $true)) {
            $flaggedSettings += "<tr class='error'><td>$($setting.Name)</td><td>Not enabled, overdue, or not up-to-date (Insecure)</td></tr>"
        } else {
            $flaggedSettings += "<tr><td>$($setting.Name)</td><td>$($setting.Value)</td></tr>"
        }
    }
    return $flaggedSettings
}

# Prompt the user for the customer name
$customerName = Read-Host "Please enter the customer name"

# Get the current date in the format yyyy-MM-dd
$currentDate = Get-Date -Format "yyyy-MM-dd"

# Get the name of the local server
$serverName = $env:COMPUTERNAME
Log-Message "Server Name: $serverName"

# Create a folder on the Desktop named "send_to_maya_<customer name>_<date>"
$folderPath = "$env:USERPROFILE\Desktop\send_to_maya_${customerName}_$currentDate"
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

# Get a list of all local users and export them to an HTML file
Log-Message "Exporting local users list..."
$users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordChangeableDate, PasswordExpires, UserMayChangePassword
Export-ToHtml -Path $usersFilePath -InputObject $users

# Get a list of all local groups and export them to an HTML file
Log-Message "Exporting local groups list..."
$groups = Get-LocalGroup | Select-Object Name, Description, SID
Export-ToHtml -Path $groupsFilePath -InputObject $groups

# Get members of each group and append them to the HTML file
Log-Message "Exporting group members list..."
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
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
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

# Get a list of all listening ports and export them to an HTML file
Log-Message "Exporting listening ports list..."
$openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress, LocalPort, OwningProcess
Export-ToHtml -Path $openPortsFilePath -InputObject $openPorts

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
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
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
        h2 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
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
        h2 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
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
        h2 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
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
