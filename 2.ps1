# All computers in domain
Get-ADComputer -Filter * -Properties OperatingSystem, IPv4Address, Description | Select Name, IPv4Address, OperatingSystem, Description

# Local admins on each machine (run on each server)
net localgroup administrators

# Check MSSQL instances (run on each server)
Get-Service | Where-Object { $_.DisplayName -like "*SQL*" }

# Check IIS
Get-WindowsFeature Web-Server

# Check ADCS
Get-WindowsFeature ADCS-Cert-Authority
certutil -config - -ping