Fase 1 — Contenimento immediato
Isola la macchina marley dalla rete (mantieni solo la comunicazione con Velociraptor):
Da Velociraptor puoi farlo con un notebook VQL direttamente su marley:

sql-- Blocca tutto il traffico verso il C2
SELECT * FROM execve(argv=["netsh", "advfirewall", "firewall", "add", "rule",
  "name=Block_C2_Havoc", "dir=out", "action=block",
  "remoteip=192.168.56.60", "enable=yes"])
Oppure se hai accesso RDP/Guacamole a marley, da cmd come admin:
cmdnetsh advfirewall firewall add rule name="Block_C2_Havoc" dir=out action=block remoteip=192.168.56.60 enable=yes
Fase 2 — Termina i processi malevoli
Killa i 3 RuntimeBroker iniettati (PID 3820, 2368, 6980):
cmdtaskkill /F /PID 3820
taskkill /F /PID 2368
taskkill /F /PID 6980
Verifica che le connessioni C2 siano cadute:
cmdnetstat -ano | findstr 192.168.56.60
Fase 3 — Rimuovi gli artefatti su disco
cmddel "C:\Users\reiner.braun\main.exe"
del "C:\Users\reiner.braun\main\main.exe"
rmdir "C:\Users\reiner.braun\main"
Fase 4 — Controlla persistenza
Verifica che l'attaccante non abbia installato meccanismi di persistenza:
cmd:: Scheduled tasks sospette
schtasks /query /fo LIST /v | findstr /i "main.exe update.exe RuntimeBroker"

:: Registry Run keys
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

:: Startup folders
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
Fase 5 — Bonifica credenziali
L'account reiner.braun è compromesso. Con un beacon Havoc attivo, l'attaccante potrebbe aver dumpato credenziali:

Resetta la password di reiner.braun sul DC di maria.local (liberio)
Resetta il krbtgt di maria.local se sospetti lateral movement
Controlla se reiner.braun ha accesso ad altri host e verifica anche quelli
