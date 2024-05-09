# Populate AD

A Script to populate Active Directory with random mock users using first names, last names, groups and passwords lists.
The users are created randomly from the lists while making sure no duplicates are created.
Run on DC with domain admin or user with appropriate privileges.

Tested on Windows Server 2012 R2 and Windows Server 2016

## How To Use

```
PS c:\> Populate-AD -NumberOfUsers 500 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt -Groups .\groups.txt -Passwords .\passwordslist.txt -CreateGroups

Description
-----------
Randomly creates 500 mock users in groups from group list.
Creates any non-existing group from group list.


PS c:\> Populate-AD -NumberOfUsers 100 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt -Passwords .\passwordslist.txt

Description
-----------
Randomly creates 100 mock users in domain users group.


PS c:\> Populate-AD -NumberOfUsers 888 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt

Description
-----------        
Randomly creates 888 mock users in domain users group with Aa123456! as password.


PS c:\> Populate-AD -NumberOfUsers 50 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt -Passwords "haha123123%"

Description
-----------        
Randomly creates 50 mock users in "Domain Users" group with haha123123% as password.


PS c:\> Populate-AD -NumberOfUsers 10 -FirstNames .\firstnames.txt -LastNames .\lastnames.txt -Groups "Domain Admins"

Description
-----------       
Randomly creates 10 mock users in "Domain Admins" group with Aa123456! as password.
```

## To-Do 

- [x] Create users and groups.
- [ ] Create and populate OUs.
- [ ] Automate misconfigurations creation (Kerberoast, ASREProast, GenericAll etc.).
