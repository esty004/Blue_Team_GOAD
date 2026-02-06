$BaseKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
$LogFile = "C:\Windows\Temp\netbios_disable.log"

"[$(Get-Date)] Avvio disabilitazione NetBIOS" | Out-File -Append $LogFile

Get-ChildItem $BaseKey | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -Type DWord
    "Disabilitato NetBIOS su $($_.PSChildName)" |
        Out-File -Append $LogFile
}

"[$(Get-Date)] Fine script" | Out-File -Append $LogFile
