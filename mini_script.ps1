# Function to log messages with a timestamp
function Log-Message {
    param (
        [string]$message,
        [string]$color = "Green"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $message" -ForegroundColor $color
}

# Function to export to HTML with styling and error highlighting
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

# Function to export user and group information, including local and AD groups
function Export-UserAndGroupInfo {
    param (
        [string]$groupsFilePath,
        [string]$groupMembersFilePath
    )
    
    $groups = Get-LocalGroup | Select-Object Name, Description, SID
    Export-ToHtml -Path $groupsFilePath -InputObject $groups

    $groupMembersContent = ""

    foreach ($group in $groups) {
        $groupName = $group.Name
        $groupMembersContent += "<h2>Group: $groupName</h2><table><tr><th>Members</th></tr>"

        try {
            if ($group.SID -match "^S-1-5-21-") {
                # Likely an AD group
                $groupMembers = Get-ADGroupMember -Identity $groupName | ForEach-Object { $_.Name }
            } else {
                # Local group
                $groupMembers = Get-LocalGroupMember -Group $groupName | ForEach-Object { $_.Name }
            }

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

# Main Script
$customerName = Read-Host "Please enter the customer name"
$customServerName = Read-Host "Please enter a custom server name"

$currentDate = Get-Date -Format "yyyy-MM-dd"
$serverName = $env:COMPUTERNAME
$ipAddress = (Test-Connection -ComputerName $serverName -Count 1).IPV4Address.IPAddressToString

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

$servicesFilePath = "$folderPath\Services_$serverName.html"
$updatesFilePath = "$folderPath\InstalledUpdates_$serverName.html"
$softwareFilePath = "$folderPath\InstalledSoftware_$serverName.html"
$gpresultFilePath = "$folderPath\GPResult_$serverName.html"
$groupsFilePath = "$folderPath\Groups_$serverName.html"
$groupMembersFilePath = "$folderPath\GroupMembers_$serverName.html"
$adPasswordPolicyFilePath = "$folderPath\ADPasswordPolicy_$serverName.html"
$openPortsFilePath = "$folderPath\OpenPorts_$serverName.html"
$sqlSecurityFilePath = "$folderPath\SQLSecurity_$serverName.html"
$summaryFilePath = "$folderPath\Summary_$serverName.html"

# Export Services
Log-Message "Exporting services list..."
$services = Get-Service | Select-Object Name, DisplayName, Status, StartType
Export-ToHtml -Path $servicesFilePath -InputObject $services

# Export Installed Updates
Log-Message "Exporting installed updates list..."
$updates = Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object HotFixID, InstalledOn
Export-ToHtml -Path $updatesFilePath -InputObject $updates

# Export Installed Software
Log-Message "Exporting installed software list..."
$software = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate
Export-ToHtml -Path $softwareFilePath -InputObject $software

# Generate GPResult
Log-Message "Generating GPResult report..."
try {
    gpresult /h $gpresultFilePath
    Log-Message "GPResult report generated: $gpresultFilePath"
} catch {
    Log-Message "Failed to generate GPResult report. $_" "Red"
}

# Export User and Group Information
Export-UserAndGroupInfo -groupsFilePath $groupsFilePath -groupMembersFilePath $groupMembersFilePath

# Check if the server is a domain controller and export AD password policy
if ((Get-WmiObject -Class Win32_ComputerSystem).DomainRole -eq 5) {
    Export-ADPasswordPolicy -policyFilePath $adPasswordPolicyFilePath
}

# Export Open Ports
Log-Message "Exporting listening ports list..."
$openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress, LocalPort, OwningProcess
Export-OpenPortsToHtml -Path $openPortsFilePath -InputObject $openPorts

# Export SQL Server Security Settings if SQL Server is installed
Export-SQLSecuritySettings -sqlSecurityFilePath $sqlSecurityFilePath

# Generate a security summary based on flagged settings
$flaggedSettings = @()  # Collect flagged settings from different checks
Generate-SecuritySummary -summaryFilePath $summaryFilePath -flaggedSettings $flaggedSettings
