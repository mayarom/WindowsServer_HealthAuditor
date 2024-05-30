try {
    New-Item -Path $HOME/result.txt -ItemType File
    New-Item -Path $HOME/debug.txt -ItemType File
    }
catch {
    Write-Output "Files already exit"
    }
finally {
$result= Get-Process -IncludeUserName | Where-Object ProcessName -Match "sql"
if (( $result )) {
    $proccess= $result.Name
    $proccessuser = $result.UserName.Split("\")[1]
    Add-Content -Path $Home/result.txt -Value "Proccess name: $proccess"
    Add-Content -Path $Home/result.txt -Value (net user $proccessuser)
    Add-Content -Path $Home/result.txt -Value "`nNote that user should not have Admin rights!"
    }
else {
    Add-Content -Path $Home/debug.txt -Value 'Proccess not found'
}
}
try {
    $result= Get-ChildItem Env:MYSQL_PWD
    if (( $result )) {
        Add-Content -Path $Home/result.txt -Value "MYSQL env variable located: $result"
    }
    else {
        Add-Content -Path $Home/result.txt -Value "`nMYSQL env variable not set"
        }
}
catch {
    Add-Content -Path $Home/debug.txt -Value "`nAn error occurred while looking for env var"
}
