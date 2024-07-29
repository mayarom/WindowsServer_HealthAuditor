# Function to log messages with a timestamp
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $message" -ForegroundColor Green
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
        Write-Error "Failed to export to CSV at $Path. $_"
    }
}

# Function to export HTML with styling
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
        Write-Error "Failed to export to HTML at $Path. $_"
    }
}

# Get the name of the local server
$serverName = $env:COMPUTERNAME
Log-Message "Server Name: $serverName"

# Create a folder on the Desktop named "Send To Maya"
$folderPath = "$env:USERPROFILE\Desktop\Send To Maya"
if (!(Test-Path $folderPath)) {
    try {
        New-Item -ItemType Directory -Path $folderPath -ErrorAction Stop | Out-Null
        Log-Message "Created folder: $folderPath"
    } catch {
        Write-Error "Failed to create folder at $folderPath. $_"
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
    Write-Error "Failed to generate GPResult report. $_"
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
    Write-Error "Failed to retrieve OS version information. $_"
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
        Write-Error "Failed to retrieve Windows features using both Get-WindowsFeature and Get-WindowsOptionalFeature."
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

# Try to export IIS configuration to XML file
Log-Message "Exporting IIS configuration..."
try {
    Import-Module WebAdministration
    $iisConfig = Get-WebConfiguration
    $iisConfig | Export-Clixml -Path $iisConfigFilePath
    Log-Message "IIS configuration exported: $iisConfigFilePath"
} catch {
    Add-Content -Path $noIisConfigFilePath -Value "No IIS Service Configured"
    Write-Error "Failed to retrieve IIS configuration. $_"
}
