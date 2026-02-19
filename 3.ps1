# IP config on each machine
ipconfig /all

# Firewall / RDP status
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections

# Defender status
Get-MpComputerStatus | Select AMRunningMode, RealTimeProtectionEnabled