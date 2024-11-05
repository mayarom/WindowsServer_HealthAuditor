#Requires -RunAsAdministrator

# הגדרת משתנים גלובליים
$ErrorActionPreference = "Stop"
$serverName = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$folderPath = Join-Path $desktopPath "SecurityAudit_$timestamp"
$gpoFilePath = Join-Path $folderPath "GPO_Settings_$serverName.html"
$installedSoftwarePath = Join-Path $folderPath "InstalledSoftware_$serverName.html"
$updateHistoryPath = Join-Path $folderPath "UpdateHistory_$serverName.html"
$localUsersPath = Join-Path $folderPath "LocalUsers_$serverName.html"
$systemInfoPath = Join-Path $folderPath "SystemInfo_$serverName.html"

# בדיקת הרשאות מנהל
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script requires administrator privileges. Please run PowerShell as Administrator."
    exit
}

# יצירת תיקיית הייצוא
if (Test-Path $folderPath) {
    try {
        Remove-Item -Path $folderPath -Recurse -Force
        Start-Sleep -Seconds 2
    }
    catch {
        Write-Error "Unable to clean up existing directory: $_"
        exit
    }
}

try {
    New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
    Write-Host "Created audit directory at: $folderPath"
}
catch {
    Write-Error "Failed to create audit directory: $_"
    exit
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

# Function to export to HTML
function Export-ToHtml {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [array]$InputObject,
        [string]$Title,
        [switch]$Fragment
    )
    
    if ($Fragment) {
        $html = $InputObject | ConvertTo-Html -Fragment
    }
    else {
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
        .critical { background-color: #ffebee; }
        .warning { background-color: #fff3e0; }
        .success { background-color: #e8f5e9; }
    </style>
</head>
<body>
<h2>$Title</h2>
"@
        $htmlFooter = "</body></html>"
        $html = $InputObject | ConvertTo-Html -Head $htmlHeader -PostContent $htmlFooter
    }
    
    try {
        Set-Content -Path $Path -Value $html -ErrorAction Stop
        Log-Message "Exported to HTML successfully: $Path"
    }
    catch {
        Log-Message "Failed to export to HTML at $Path. $_" "Red"
    }
}

# Function to export GPO settings
function Export-GPOSettings {
    param (
        [string]$Path
    )
    
    Log-Message "Collecting GPO settings..."
    try {
        $gpoSettings = @()
        
        # Security Policy Settings
        $securitySettings = secedit /export /cfg "$env:TEMP\secpol.cfg" 2>&1
        if (Test-Path "$env:TEMP\secpol.cfg") {
            $secpolContent = Get-Content "$env:TEMP\secpol.cfg" | Where-Object { $_ -match '=' }
            foreach ($line in $secpolContent) {
                if ($line -match '(.+?)=(.+)') {
                    $gpoSettings += [PSCustomObject]@{
                        Category = "Security Policy"
                        Setting = $matches[1].Trim()
                        Value = $matches[2].Trim()
                    }
                }
            }
            Remove-Item "$env:TEMP\secpol.cfg" -Force
        }

        # System Access Policies
        $systemPolicies = @(
            "SePasswordComplexity",
            "SePasswordComplexityEnabled",
            "SeMinimumPasswordLength",
            "SeMaximumPasswordAge",
            "SeMinimumPasswordAge",
            "SeLockoutBadCount",
            "SeLockoutDuration"
        )

        foreach ($policy in $systemPolicies) {
            try {
                $value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name $policy -ErrorAction SilentlyContinue).$policy
                if ($null -ne $value) {
                    $gpoSettings += [PSCustomObject]@{
                        Category = "System Access Policy"
                        Setting = $policy
                        Value = $value
                    }
                }
            }
            catch {}
        }

        # Audit Policies
        $auditPolicies = auditpol /get /category:* /r | ConvertFrom-Csv
        foreach ($policy in $auditPolicies) {
            $gpoSettings += [PSCustomObject]@{
                Category = "Audit Policy"
                Setting = $policy.'Subcategory'
                Value = $policy.'Inclusion Setting'
            }
        }

        # Export to HTML
        Export-ToHtml -Path $Path -InputObject $gpoSettings -Title "Group Policy Settings"
        Log-Message "GPO settings exported successfully"
    }
    catch {
        Log-Message "Error exporting GPO settings: $_" "Red"
    }
}

# Function to export installed software
function Export-InstalledSoftware {
    param (
        [string]$Path
    )
    
    Log-Message "Collecting installed software information..."
    try {
        $software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Where-Object DisplayName -ne $null

        $software += Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Where-Object DisplayName -ne $null

        $sortedSoftware = $software | Sort-Object DisplayName | ForEach-Object {
            # Convert InstallDate to readable format if possible
            if ($_.InstallDate -match '(\d{4})(\d{2})(\d{2})') {
                $installDate = "$($matches[1])-$($matches[2])-$($matches[3])"
            }
            else {
                $installDate = $_.InstallDate
            }

            [PSCustomObject]@{
                'Name' = $_.DisplayName
                'Version' = $_.DisplayVersion
                'Publisher' = $_.Publisher
                'Install Date' = $installDate
            }
        }

        Export-ToHtml -Path $Path -InputObject $sortedSoftware -Title "Installed Software"
        Log-Message "Installed software information exported successfully"
    }
    catch {
        Log-Message "Error exporting installed software information: $_" "Red"
    }
}

# Function to export update history
function Export-UpdateHistory {
    param (
        [string]$Path
    )
    
    Log-Message "Collecting update history..."
    try {
        $updates = Get-HotFix | Select-Object @{
            Name='Installation Date'
            Expression={$_.InstalledOn}
        }, 
        Description,
        HotFixID,
        @{
            Name='Type'
            Expression={
                switch -Regex ($_.Description) {
                    'Security Update|Critical Update' { 'Security' }
                    'Update' { 'Regular Update' }
                    default { 'Other' }
                }
            }
        }

        $sortedUpdates = $updates | Sort-Object 'Installation Date' -Descending

        Export-ToHtml -Path $Path -InputObject $sortedUpdates -Title "Windows Update History"
        Log-Message "Update history exported successfully"
    }
    catch {
        Log-Message "Error exporting update history: $_" "Red"
    }
}

# Function to export local users information
function Export-LocalUsers {
    param (
        [string]$Path
    )
    
    Log-Message "Collecting local users information..."
    try {
        $users = Get-LocalUser | ForEach-Object {
            $user = $_
            $userInfo = net user $user.Name | Where-Object { $_ -match ":" }
            $lastPasswordSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            $passwordExpires = if ($user.PasswordExpires) { $user.PasswordExpires.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            
            # Extract last logon from net user output
            $lastLogon = ($userInfo | Where-Object { $_ -match "Last logon" }) -replace "Last logon", "" -replace "\s+", " "

            [PSCustomObject]@{
                'Username' = $user.Name
                'Enabled' = $user.Enabled
                'Description' = $user.Description
                'Created' = $user.Created.ToString("yyyy-MM-dd HH:mm:ss")
                'Last Password Set' = $lastPasswordSet
                'Password Expires' = $passwordExpires
                'Password Required' = $user.PasswordRequired
                'Last Logon' = $lastLogon.Trim()
                'Account Expires' = if ($user.AccountExpires) { $user.AccountExpires.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            }
        }

        Export-ToHtml -Path $Path -InputObject $users -Title "Local Users Information"
        Log-Message "Local users information exported successfully"
    }
    catch {
        Log-Message "Error exporting local users information: $_" "Red"
    }
}

# Function to export system information
function Export-SystemInformation {
    param (
        [string]$Path
    )
    
    Log-Message "Collecting system information..."
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_BIOS
        
        $systemInfo = [PSCustomObject]@{
            'Computer Name' = $env:COMPUTERNAME
            'OS Version' = $os.Caption
            'OS Build' = $os.BuildNumber
            'OS Architecture' = $os.OSArchitecture
            'Install Date' = $os.InstallDate.ToString("yyyy-MM-dd HH:mm:ss")
            'Last Boot Time' = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
            'System Manufacturer' = $cs.Manufacturer
            'System Model' = $cs.Model
            'BIOS Version' = $bios.SMBIOSBIOSVersion
            'Total Physical Memory (GB)' = [math]::Round($cs.TotalPhysicalMemory/1GB, 2)
            'Domain' = $cs.Domain
            'Time Zone' = (Get-TimeZone).DisplayName
        }

        Export-ToHtml -Path $Path -InputObject $systemInfo -Title "System Information"
        Log-Message "System information exported successfully"
    }
    catch {
        Log-Message "Error exporting system information: $_" "Red"
    }
}

# Main execution
try {
    Log-Message "Starting security audit..."
    
    # יצירת מערך של משימות והרצתן
    $tasks = @(
        @{ Name = "GPO Settings"; Action = { Export-GPOSettings -Path $gpoFilePath } },
        @{ Name = "Installed Software"; Action = { Export-InstalledSoftware -Path $installedSoftwarePath } },
        @{ Name = "Update History"; Action = { Export-UpdateHistory -Path $updateHistoryPath } },
        @{ Name = "Local Users"; Action = { Export-LocalUsers -Path $localUsersPath } },
        @{ Name = "System Information"; Action = { Export-SystemInformation -Path $systemInfoPath } }
    )

    foreach ($task in $tasks) {
        try {
            Log-Message "Starting task: $($task.Name)..."
            & $task.Action
            Log-Message "Completed task: $($task.Name)"
        }
        catch {
            Log-Message "Error in task $($task.Name): $_" "Red"
        }
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
    
    Log-Message "Security audit completed successfully."
    Log-Message "All reports have been saved to: $folderPath"
    
# פתיחת תיקיית הדוחות
    try {
        Start-Process explorer.exe -ArgumentList $folderPath
    }
    catch {
        Log-Message "Failed to open reports folder. Please navigate to: $folderPath" "Yellow"
    }
}
catch {
    Log-Message "An error occurred during the audit process: $_" "Red"
}
finally {
    # Reset ErrorActionPreference to default
    $ErrorActionPreference = "Continue"
}

# הוספת סיכום ממצאים חשובים
$summaryPath = Join-Path $folderPath "SecurityFindings_Summary.html"
try {
    $criticalFindings = @()

    # בדיקת עדכונים אחרונים
    $lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $daysSinceLastUpdate = (Get-Date) - $lastUpdate.InstalledOn
    if ($daysSinceLastUpdate.Days -gt 30) {
        $criticalFindings += [PSCustomObject]@{
            Category = "Updates"
            Finding = "No security updates installed in the last 30 days"
            Severity = "High"
            Recommendation = "Install all pending security updates"
        }
    }

    # בדיקת משתמשים לא פעילים
    $inactiveThreshold = (Get-Date).AddDays(-90)
    $inactiveUsers = Get-LocalUser | Where-Object {
        $_.Enabled -and $_.LastLogon -ne $null -and $_.LastLogon -lt $inactiveThreshold
    }
    if ($inactiveUsers) {
        $criticalFindings += [PSCustomObject]@{
            Category = "User Accounts"
            Finding = "Found $($inactiveUsers.Count) inactive user accounts (no login for 90+ days)"
            Severity = "Medium"
            Recommendation = "Review and disable inactive accounts"
        }
    }

    # בדיקת מדיניות סיסמאות
    $passwordPolicy = Get-LocalSecurityPolicy
    if ($passwordPolicy.PasswordComplexity -eq 0) {
        $criticalFindings += [PSCustomObject]@{
            Category = "Password Policy"
            Finding = "Password complexity is not enforced"
            Severity = "High"
            Recommendation = "Enable password complexity requirements"
        }
    }

    if ($criticalFindings.Count -gt 0) {
        $summaryContent = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #2e6c80; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .High { background-color: #ffebee; }
        .Medium { background-color: #fff3e0; }
        .Low { background-color: #e8f5e9; }
    </style>
</head>
<body>
<h1>Critical Security Findings</h1>
<table>
    <tr>
        <th>Category</th>
        <th>Finding</th>
        <th>Severity</th>
        <th>Recommendation</th>
    </tr>
"@

        foreach ($finding in $criticalFindings) {
            $summaryContent += @"
    <tr class="$($finding.Severity)">
        <td>$($finding.Category)</td>
        <td>$($finding.Finding)</td>
        <td>$($finding.Severity)</td>
        <td>$($finding.Recommendation)</td>
    </tr>
"@
        }

        $summaryContent += @"
</table>
</body>
</html>
"@

        Set-Content -Path $summaryPath -Value $summaryContent
        Log-Message "Critical findings summary generated: $summaryPath"
    }
}
catch {
    Log-Message "Error generating critical findings summary: $_" "Red"
}

# Function to get local security policy
function Get-LocalSecurityPolicy {
    $securityPolicy = @{}
    $secpolContent = secedit /export /cfg "$env:TEMP\secpol.cfg" 2>&1
    if (Test-Path "$env:TEMP\secpol.cfg") {
        Get-Content "$env:TEMP\secpol.cfg" | ForEach-Object {
            if ($_ -match '(.+?)=(.+)') {
                $securityPolicy[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        Remove-Item "$env:TEMP\secpol.cfg" -Force
    }
    return [PSCustomObject]$securityPolicy
}    
