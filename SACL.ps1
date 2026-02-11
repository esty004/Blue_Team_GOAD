# Importa il modulo AD
Import-Module ActiveDirectory

# Ottieni il Distinguished Name del dominio
$domainDN = (Get-ADDomain).DistinguishedName

# Ottieni il SID di Everyone
$everyoneSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")

# Crea la regola di audit
$guid1 = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" # DS-Replication-Get-Changes
$guid2 = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" # DS-Replication-Get-Changes-All
$guid3 = [GUID]"89e95b76-444d-4c62-991a-0facbeda640c" # DS-Replication-Get-Changes-In-Filtered-Set

# Ottieni l'ACL corrente
$acl = Get-Acl -Path "AD:$domainDN" -Audit

# Aggiungi le regole di audit
$auditRule1 = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyoneSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AuditFlags]::Success,
    $guid1,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

$auditRule2 = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyoneSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AuditFlags]::Success,
    $guid2,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

$auditRule3 = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyoneSID,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AuditFlags]::Success,
    $guid3,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

# Applica le regole
$acl.AddAuditRule($auditRule1)
$acl.AddAuditRule($auditRule2)
$acl.AddAuditRule($auditRule3)

# Salva le modifiche
Set-Acl -Path "AD:$domainDN" -AclObject $acl
