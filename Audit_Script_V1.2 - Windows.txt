# Get the name of the local server
$serverName = $env:COMPUTERNAME

# Create a folder on the Desktop named "Send To Maya"
$folderPath = "$env:USERPROFILE\Desktop\Send To Maya"
if (!(Test-Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Define the file path for all the files
$servicesFilePath = "$folderPath\Services_$serverName.csv"
$updatesFilePath = "$folderPath\InstalledUpdates_$serverName.csv"
$softwareFilePath = "$folderPath\InstalledSoftware_$serverName.csv"
$gpresultFilePath = "$folderPath\GPResult_$serverName.html"
$usersFilePath = "$folderPath\Users_$serverName.csv"
$groupsFilePath = "$folderPath\Groups_$serverName.csv"
$groupMembersFilePath = "$folderPath\GroupMembers_$serverName.txt"
$windowsFeaturesFilePath = "$folderPath\WindowsFeatures_$serverName.txt"
$openPortsFilePath = "$folderPath\OpenPorts_$serverName.csv"
$sharedFoldersFilePath = "$folderPath\SharedFolders_$serverName.csv"
$osVersionFilePath = "$folderPath\OSVersion_$serverName.txt"
$iisConfigFilePath = "$folderPath\IISConfig_$serverName.xml"
$noIisConfigFilePath = "$folderPath\NoIISConfig_$serverName.txt"

# Get a list of all services on the server and export them to a CSV file
Get-Service | 
    Select-Object Name, DisplayName, Status, StartType | 
    Export-Csv -Path $servicesFilePath -NoTypeInformation

# Get a list of all installed security updates on the server and export them to a CSV file
Get-WmiObject -Class Win32_QuickFixEngineering | 
    Select-Object HotFixID, InstalledOn | 
    Export-Csv -Path $updatesFilePath -NoTypeInformation

# Get a list of all installed software on the local server and export them to a CSV file
Get-WmiObject -Class Win32_Product | 
    Select-Object Name, Version, VenMaya, InstallDate | 
    Export-Csv -Path $softwareFilePath -NoTypeInformation

# Get GPResult and save it to the HTML file
gpresult /h $gpresultFilePath

# Get a list of all local users and export them to a CSV file
Get-LocalUser | 
    Select-Object Name, Enabled, LastLogon, PasswordChangeableDate, PasswordExpires, UserMayChangePassword | 
    Export-Csv -Path $usersFilePath -NoTypeInformation

# Get a list of all local groups and export them to a CSV file
Get-LocalGroup | 
    Select-Object Name, Description, SID | 
    Export-Csv -Path $groupsFilePath -NoTypeInformation

# Get members of each group and append them to the TXT file
Get-LocalGroup | ForEach-Object {
    $groupName = $_.Name
    Add-Content -Path $groupMembersFilePath -Value "`n`nGroup: $groupName`n=========="
    $groupMembers = Get-LocalGroupMember -Group $_ | Select-Object -ExpandProperty Name
    if ($groupMembers) {
        Add-Content -Path $groupMembersFilePath -Value $groupMembers
    } else {
        Add-Content -Path $groupMembersFilePath -Value "No users in this group"
    }
}

# Get a list of all listening ports and export them to a CSV file
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | 
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Export-Csv -Path $openPortsFilePath -NoTypeInformation

# Get a list of all shared folders on the server and export them to a CSV file
Get-WmiObject -Class Win32_Share |
    Select-Object Name, Path, Description |
    Export-Csv -Path $sharedFoldersFilePath -NoTypeInformation

# Get the operating system version and export it to a TXT file
$osVersion = Get-WmiObject -Class Win32_OperatingSystem | 
    Select-Object Caption, Version, BuildNumber, OSArchitecture
$osVersionInfo = "Name: $($osVersion.Caption)`nVersion: $($osVersion.Version)`nBuild Number: $($osVersion.BuildNumber)`nArchitecture: $($osVersion.OSArchitecture)"
Add-Content -Path $osVersionFilePath -Value $osVersionInfo

# Try to get a list of all installed Windows features using Get-WindowsFeature
$windowsFeatures = $null
try {
    $windowsFeatures = Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"} | Select-Object -ExpandProperty Name
    $commandUsed = "Get-WindowsFeature"
} catch {
    # If Get-WindowsFeature fails, try Get-WindowsOptionalFeature
    try {
        $windowsFeatures = Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"} | Select-Object -ExpandProperty FeatureName
        $commandUsed = "Get-WindowsOptionalFeature"
    } catch {
        Write-Error "Failed to retrieve Windows features using both Get-WindowsFeature and Get-WindowsOptionalFeature."
    }
}

# Add the list of Windows features to the TXT file
if ($windowsFeatures) {
    Add-Content -Path $windowsFeaturesFilePath -Value "The command used to retrieve these features was: $commandUsed`n`n"
    $windowsFeatures | ForEach-Object {
        Add-Content -Path $windowsFeaturesFilePath -Value $_
    }
}

# Try to export IIS configuration to XML file
try {
    Import-Module WebAdministration
    $iisConfig = Get-WebConfiguration
    $iisConfig | Export-Clixml -Path $iisConfigFilePath
} catch {
    # If IIS is not found or any other error occurs, create a TXT file with the specified message
    Add-Content -Path $noIisConfigFilePath -Value "No IIS Service Configured"
}
