function Populate-AD{
    <# 
    .SYNOPSIS

        Populates Active Directory with mock users.

    .DESCRIPTION

        Populates Active Directory with random mock users using first names, last names, groups and passwords lists.
        The users are created randomly from the lists while making sure no duplicates are created.
        Run on DC with domain admin or user with appropriate privileges.

        Tested on Windows Server 2012 R2 and Windows Server 2016.
        Author: Tamir Yehuda @Tamirye94

    .PARAMETER NumberOfUsers

        The number of users to be created.

    .PARAMETER FirstNamesFile

        points to the path of the first names list file.

    .PARAMETER LastNamesFile

        points to the path of the last names list file.

    .PARAMETER Groups

        points to the path of the groups list file or a specific group.
        if left empty will default to Domain users group.

    .PARAMETER CreateGroups

        if a group does not exist it is created, take note that no special privileges are granted to the new groups.

    .PARAMETER Passwords

        points to the path of the password list file or a specific password.
        if left empty will default to Aa123456! 

    .EXAMPLE

        PS c:\> Populate-AD -NumberOfUsers 500 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt -Groups .\groups.txt -Passwords .\passwordslist.txt -CreateGroups

        Description
        -----------
        Randomly creates 500 mock users in groups from group list.
        Creates any non-existing group from group list.

    .EXAMPLE

        PS c:\> Populate-AD -NumberOfUsers 100 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt -Passwords .\passwordslist.txt

        Description
        -----------
        Randomly creates 100 mock users in domain users group.

    .EXAMPLE

        PS c:\> Populate-AD -NumberOfUsers 888 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt

        Description
        -----------        
        Randomly creates 888 mock users in domain users group with Aa123456! as password.

    .EXAMPLE

        PS c:\> Populate-AD -NumberOfUsers 50 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt -Passwords "haha123123%"

        Description
        -----------        
        Randomly creates 50 mock users in "Domain Users" group with haha123123% as password.

    .EXAMPLE

        PS c:\> Populate-AD -NumberOfUsers 10 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt -Groups "Domain Admins"

        Description
        -----------       
        Randomly creates 10 mock users in "Domain Admins" group with Aa123456! as password.

    #>
    param(

    [Parameter(Mandatory = $true)]
    [int] 
    $NumberOfUsers=1,

    [Parameter(Mandatory = $true)]
    [string] 
    $FirstNamesFile,

    [Parameter(Mandatory = $true)]
    [string] 
    $LastNamesFile,
    
    [Parameter(Mandatory = $false)]
    [string] 
    $Groups='Domain Users',

    [Parameter(Mandatory = $false)]
    [string] $Passwords = "Aa123456!",

    [Parameter(Mandatory = $false)]
    [switch] $CreateGroups

    )

    Import-Module ActiveDirectory
    $domain = $env:userdnsdomain
    $fqdn =  Get-ADDomain | select -ExpandProperty DistinguishedName


    # checks if CreateGroups is set, if so create all new groups
    if($CreateGroups)
    {
        Write-Host "[+] CreateGroups Flag is set"
        if($Groups -ne "Domain Users"){
            Write-Host "[+] Creating non-existing groups!"
            Write-Host "[!] Created Groups will not have any priviliges deligated to them, please set appropriate priviliges manually!"
            $groupPath = "CN=Users," + $fqdn
            if (Test-Path $Groups)
            {
                foreach($g in Get-Content $Groups)
                {
                    try {
                        Get-ADGroup $g | Out-Null
                    } Catch {
                        $description = $g + " Group"
                        New-ADGroup -Name $g -SamAccountName $g -GroupScope Global -DisplayName $g -Path $groupPath -Description $description
                        Write-Host "[+] $g group was created!"
                    }
                }
            } else {
                try {
                        Get-ADGroup $Groups | Out-Null
                    } Catch {
                        $description = $Groups + " Group"
                        New-ADGroup -Name $Groups -SamAccountName $Groups -GroupScope Global -DisplayName $Groups -Path $groupPath -Description $description
                        Write-Host "[+] $Groups group was created!"
                    }
            }
             Write-Host "[+] Done!"
        } else {
            Write-Host "[!] -Groups parameter not supplied!, no group will be created and all new users will be only part of the Domain Users only"
        }
    }
    
    Write-Host "[+] Creating Users"
    for( $i = 1; $i -le $NumberOfUsers; $i ++)
    {
        $flag = $true
        if(Test-Path $Passwords) 
        {
            $securePassword = ConvertTo-SecureString -AsPlainText (Get-Random -InputObject (Get-Content $Passwords)) -Force
        } else {
            $securePassword = ConvertTo-SecureString -AsPlainText $Passwords -Force
        }
        $firstname = Get-Random -InputObject (Get-Content $FirstNamesFile)
        $lastname = Get-Random -InputObject (Get-Content $LastNamesFile)
        $username = $firstname + ' ' + $lastname

        $error.clear()
        try
        {
            Get-ADUser $username | Out-Null
        } catch {
            $flag = $false
            $sam = $firstname + '.' + $lastname
            $principalName =  $sam + '@' + $domain 
            $addCommand = New-ADUser -Name $username -GivenName $firstname -Surname $lastname -SamAccountName $sam -UserPrincipalName $principalName -AccountPassword $securePassword -Enabled $true

            if($Groups -ne "Domain Users")
            {
                if(Test-Path $Groups)
                {
                    $group = Get-Random -InputObject (Get-Content $Groups)
                } else {
                    $group = $Groups
                }
                try {
                    Add-ADGroupMember -Identity $group -Members $sam
                } catch {
                    Write-Host "[!] Group + $group + doesn't exist, if you want this group to be created use -CreateGroups parameter and run again"
                }
            }
        }
        if($flag) {
            $i--
        }
        
    }
    Write-Host "[+] Done!"
}