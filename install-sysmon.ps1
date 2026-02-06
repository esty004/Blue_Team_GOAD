$SysmonDir = "C:\Sysmon"
$SysmonZip = "$SysmonDir\Sysmon.zip"
$SysmonExe = "$SysmonDir\Sysmon64.exe"
$SysmonConfig = "$SysmonDir\sysmonconfig.xml"

# Crea directory
if (-not (Test-Path $SysmonDir)) {
    New-Item -ItemType Directory -Path $SysmonDir
}

# Download Sysmon
Invoke-WebRequest `
    -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile $SysmonZip

# Estrai Sysmon
Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force

# Download configurazione SwiftOnSecurity
Invoke-WebRequest `
    -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile $SysmonConfig

# Installa Sysmon
Start-Process `
    -FilePath $SysmonExe `
    -ArgumentList "-accepteula -i `"$SysmonConfig`"" `
    -Wait `
    -NoNewWindow
