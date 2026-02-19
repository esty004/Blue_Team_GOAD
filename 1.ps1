# Domain & Forest info
Get-ADForest
Get-ADDomain
(Get-ADForest).Domains | ForEach-Object { Get-ADDomain -Identity $_ }

# Trust relationships
Get-ADTrust -Filter *

# Domain Controllers
Get-ADDomainController -Filter * | Select Name, IPv4Address, OperatingSystem, Domain

# All users (highlight privileged)
Get-ADUser -Filter * -Properties MemberOf, Description, LastLogonDate | Select SamAccountName, Enabled, Description, LastLogonDate, @{N='Groups';E={$_.MemberOf -join '; '}}

# Domain Admins & Enterprise Admins
Get-ADGroupMember "Domain Admins" -Recursive | Select Name, SamAccountName
Get-ADGroupMember "Enterprise Admins" -Recursive | Select Name, SamAccountName

# All security groups and members
Get-ADGroup -Filter * | ForEach-Object { [PSCustomObject]@{ Group=$_.Name; Members=(Get-ADGroupMember $_ | Select -Expand SamAccountName) -join ', ' } }