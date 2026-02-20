# Guida Integrazione YARA e Sigma Rules — Lab ITS AD Security

## Indice

1. [YARA Rules — Integrazione in Velociraptor](#1-yara-rules--integrazione-in-velociraptor)
2. [YARA Rules — Scansione manuale su endpoint](#2-yara-rules--scansione-manuale-su-endpoint)
3. [Sigma Rules — Conversione per Wazuh](#3-sigma-rules--conversione-per-wazuh)
4. [Sigma Rules — Conversione per ELK](#4-sigma-rules--conversione-per-elk)
5. [Sigma Rules — Integrazione in Velociraptor](#5-sigma-rules--integrazione-in-velociraptor)
6. [Riepilogo architettura](#6-riepilogo-architettura)

---

## 1. YARA Rules — Integrazione in Velociraptor

Il modo più efficace di usare le YARA rules nel lab è tramite Velociraptor, che può lanciare
scansioni YARA su disco e in memoria di tutti gli endpoint contemporaneamente.

### 1.1 Caricare le regole sul server Velociraptor

Accedi al server Velociraptor (https://192.168.56.53:8889) e vai su:

**Server Artifacts → Notebook → New Notebook**

Carica il file `ad_attack_rules.yar` come risorsa, oppure incollalo in un artifact custom.

### 1.2 Artifact per scansione YARA su disco

Crea un nuovo artifact in Velociraptor (View Artifacts → Add an Artifact):

```yaml
name: Windows.Custom.YaraScan.ADAttacks
description: Scansione YARA per MoonSniper e tool di attacco AD
type: CLIENT

parameters:
  - name: ScanPath
    default: "C:/Users"
    description: Path da scansionare

  - name: YaraRules
    default: |
      rule MoonSniper_Loader {
        meta:
          description = "MoonSniper shellcode loader"
        strings:
          $pdb = "MoonSniper.pdb" ascii wide
          $rc4_key = "RuntimeBroker.exe" wide
          $api1 = "VirtualAllocEx" ascii
          $api2 = "WriteProcessMemory" ascii
          $api3 = "QueueUserAPC" ascii
        condition:
          uint16(0) == 0x5A4D and ($pdb or ($rc4_key and 2 of ($api*)))
      }

      rule Mimikatz_Generic {
        meta:
          description = "Mimikatz e varianti"
        strings:
          $s1 = "mimikatz" ascii wide nocase
          $s2 = "gentilkiwi" ascii wide
          $s3 = "sekurlsa" ascii wide
          $s4 = "lsadump" ascii wide
          $s5 = "kerberos::golden" ascii wide nocase
          $s6 = "privilege::debug" ascii wide nocase
        condition:
          3 of them
      }

      rule BloodHound_SharpHound {
        meta:
          description = "SharpHound AD collector"
        strings:
          $sh1 = "SharpHound" ascii wide nocase
          $sh2 = "BloodHound" ascii wide nocase
          $sh3 = "Invoke-BloodHound" ascii wide nocase
          $out1 = "_BloodHound.zip" ascii wide nocase
        condition:
          2 of them
      }

      rule Rubeus_Kerberoast {
        meta:
          description = "Rubeus Kerberoasting tool"
        strings:
          $r1 = "Rubeus" ascii wide nocase
          $r2 = "kerberoast" ascii wide nocase
          $r3 = "asreproast" ascii wide nocase
          $r4 = "$krb5tgs$" ascii wide
        condition:
          2 of them
      }

sources:
  - name: FileScan
    query: |
      SELECT FullPath, Name, Size, Mtime,
             hash(path=FullPath, hashselect="SHA256") AS Hash,
             Rule AS YaraRule,
             Meta AS YaraMeta
      FROM foreach(
        row={
          SELECT FullPath, Name, Size, Mtime
          FROM glob(globs=ScanPath + "/**/*.exe")
          WHERE NOT IsDir AND Size < 50000000
        },
        query={
          SELECT FullPath, Name, Size, Mtime, Rule, Meta
          FROM yara(files=FullPath, rules=YaraRules)
        }
      )
```

### 1.3 Scansione YARA in memoria

Per scansionare la memoria dei processi attivi (cerca beacon Havoc, Mimikatz in memoria, ecc.):

```yaml
name: Windows.Custom.YaraMemoryScan.ADAttacks
description: Scansione YARA in memoria processi
type: CLIENT

parameters:
  - name: ProcessNameRegex
    default: "."
    description: Regex per filtrare processi

  - name: YaraRules
    default: |
      rule Havoc_Beacon_Memory {
        strings:
          $inet1 = "wininet.dll" ascii wide
          $inet2 = "HttpSendRequestA" ascii
          $c2_1 = "192.168.56.60" ascii wide
          $c2_2 = "10.0.2.15" ascii wide
        condition:
          any of ($inet*) and any of ($c2_*)
      }

      rule Mimikatz_InMemory {
        strings:
          $s1 = "mimikatz" ascii wide nocase
          $s2 = "sekurlsa" ascii wide
          $s3 = "gentilkiwi" ascii wide
          $s4 = "lsadump" ascii wide
        condition:
          2 of them
      }

sources:
  - name: MemoryScan
    query: |
      SELECT * FROM foreach(
        row={
          SELECT Pid, Name, Exe, Username
          FROM pslist()
          WHERE Name =~ ProcessNameRegex
        },
        query={
          SELECT Pid, Name, Exe, Username,
                 Rule AS YaraRule,
                 HitOffset, HitContext
          FROM yara(pid=Pid, rules=YaraRules)
        }
      )
```

### 1.4 Lanciare come Hunt

1. Vai su **Hunt Manager → New Hunt**
2. Seleziona l'artifact `Windows.Custom.YaraScan.ADAttacks`
3. Configura il `ScanPath` (default: `C:/Users`)
4. Target: **All clients**
5. Lancia il Hunt

I risultati mostreranno ogni file che matcha una YARA rule con il nome della regola,
il path completo e l'hash SHA256.

---

## 2. YARA Rules — Scansione manuale su endpoint

Se vuoi eseguire YARA direttamente su una macchina Windows senza Velociraptor:

### 2.1 Installazione YARA su Windows

Scarica il binario da: https://github.com/VirusTotal/yara/releases

Copia `yara64.exe` e `yarac64.exe` nella macchina target.

### 2.2 Scansione

```cmd
:: Scansione di una directory
yara64.exe ad_attack_rules.yar C:\Users\ -r

:: Scansione di un singolo file
yara64.exe ad_attack_rules.yar C:\Users\reiner.braun\main.exe

:: Scansione di un processo in memoria (per PID)
yara64.exe ad_attack_rules.yar 3820

:: Output verbose con dettagli match
yara64.exe -s ad_attack_rules.yar C:\Users\ -r
```

---

## 3. Sigma Rules — Conversione per Wazuh

Le Sigma rules sono un formato universale che deve essere convertito nel formato
specifico del tuo SIEM. Per Wazuh, la conversione produce regole XML.

### 3.1 Installazione sigma-cli

Sul tuo PC (non sul server Wazuh):

```bash
pip install sigma-cli
pip install pySigma-backend-wazuh
pip install pySigma-pipeline-sysmon
```

### 3.2 Conversione

```bash
# Converti le regole MoonSniper
sigma convert -t wazuh -p sysmon sigma_moonsniper.yml -o wazuh_sigma_moonsniper.xml

# Converti Zerologon/DCSync/Kerberoasting
sigma convert -t wazuh sigma_zerologon_dcsync_kerberoast.yml -o wazuh_sigma_zerologon.xml

# Converti Golden Ticket/ASREP/BloodHound/LSASS
sigma convert -t wazuh sigma_golden_asrep_bloodhound_lsass.yml -o wazuh_sigma_golden.xml
```

### 3.3 Installazione su Wazuh Manager

```bash
# SSH sul server Wazuh
ssh vagrant@192.168.56.51
sudo su -

# Copia i file convertiti
cp wazuh_sigma_*.xml /var/ossec/etc/rules/

# Riavvia
systemctl restart wazuh-manager

# Verifica
grep -i "error" /var/ossec/logs/ossec.log | tail -5
```

### 3.4 Conversione manuale (se sigma-cli non è disponibile)

Se non puoi installare sigma-cli, le Sigma rules vanno convertite manualmente.
Ecco la mappatura:

| Sigma field | Wazuh field |
|---|---|
| `Image\|endswith` | `<field name="win.eventdata.image" type="pcre2">(?i)\\\\valore$</field>` |
| `CommandLine\|contains` | `<field name="win.eventdata.commandLine" type="pcre2">(?i)valore</field>` |
| `ParentImage\|endswith` | `<field name="win.eventdata.parentImage" type="pcre2">(?i)\\\\valore$</field>` |
| `DestinationIp` | `<field name="win.eventdata.destinationIp">valore</field>` |
| `TargetImage\|endswith` | `<field name="win.eventdata.targetImage" type="pcre2">(?i)\\\\valore$</field>` |
| `GrantedAccess` | `<field name="win.eventdata.grantedAccess">valore</field>` |
| `EventID` | la regola base 0595 già filtra per EventID tramite `<if_group>sysmon_eventX</if_group>` |

Esempio di conversione manuale della Sigma rule Kerberoasting → Wazuh:

**Sigma:**
```yaml
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
        Status: '0x0'
    filter_machine:
        ServiceName|endswith: '$'
    condition: selection and not filter_machine
level: high
```

**Wazuh XML:**
```xml
<rule id="100200" level="10">
  <if_sid>60138</if_sid>  <!-- regola base per Event 4769 -->
  <field name="win.eventdata.ticketEncryptionType">0x17</field>
  <field name="win.eventdata.status">0x0</field>
  <field name="win.eventdata.serviceName" negate="yes" type="pcre2">\$$</field>
  <description>Kerberoasting: TGS Request con RC4 encryption</description>
  <mitre><id>T1558.003</id></mitre>
  <group>kerberoasting,credential_access,</group>
</rule>
```

---

## 4. Sigma Rules — Conversione per ELK

Il tuo lab ha ELK su http://192.168.56.50:5601. Puoi usare le Sigma rules
come query KQL o Lucene in Kibana.

### 4.1 Conversione con sigma-cli

```bash
pip install pySigma-backend-elasticsearch

# Converti in formato Lucene (per Kibana Discover)
sigma convert -t elasticsearch -p sysmon sigma_moonsniper.yml

# Converti in formato ES|QL
sigma convert -t elasticsearch --backend-option query_type=esql sigma_moonsniper.yml
```

### 4.2 Importazione in Kibana Detection Rules

1. Vai su **Kibana → Security → Rules → Detection Rules → Create New Rule**
2. Seleziona **Custom Query**
3. Incolla la query convertita
4. Configura severity, schedule (ogni 5 minuti), e azioni (alert)
5. Salva e attiva

### 4.3 Esempio query KQL per MoonSniper in Kibana

```
winlog.event_data.Image: (*MoonSniper.exe OR *\\main.exe) AND winlog.event_id: "1"
```

```
winlog.event_data.DestinationIp: "192.168.56.60" AND winlog.event_id: "3"
```

```
winlog.event_data.TargetImage: *RuntimeBroker.exe AND winlog.event_data.GrantedAccess: ("0x1fffff" OR "0x001f0fff" OR "0x0028") AND winlog.event_id: "10"
```

---

## 5. Sigma Rules — Integrazione in Velociraptor

Velociraptor ha un artifact built-in per eseguire Sigma rules direttamente.

### 5.1 Usare l'artifact Windows.Detection.Sigma

1. In Velociraptor vai su **Collected Artifacts → New Collection**
2. Cerca `Windows.Detection.Sigma.Process`
3. Nel campo **SigmaRules** incolla il contenuto YAML delle Sigma rules
4. Lancia la collection

### 5.2 Artifact custom con Sigma embedded

```yaml
name: Windows.Custom.Sigma.ADAttacks
description: Sigma rules per attacchi AD via log Sysmon
type: CLIENT

parameters:
  - name: SysmonLogPath
    default: "C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"
  - name: SecurityLogPath
    default: "C:/Windows/System32/winevt/Logs/Security.evtx"
  - name: LookbackHours
    default: 24

sources:
  - name: Sysmon_Sigma_Scan
    description: Applica Sigma rules ai log Sysmon
    query: |
      LET start_time = now() - LookbackHours * 3600000000000

      LET events = SELECT *
        FROM parse_evtx(
          filename=SysmonLogPath
        )
        WHERE System.TimeCreated.SystemTime > start_time

      -- MoonSniper loader
      LET moonsniper = SELECT
          System.TimeCreated.SystemTime AS Timestamp,
          "MoonSniper_Loader" AS SigmaRule,
          "critical" AS Level,
          EventData.Image AS Image,
          EventData.CommandLine AS CommandLine,
          EventData.User AS User,
          System.Computer AS Computer
        FROM events
        WHERE System.EventID.Value = 1
          AND (EventData.Image =~ "(?i)(MoonSniper|\\\\main)\\.exe$"
               OR EventData.OriginalFileName = "MoonSniper.exe")

      -- RuntimeBroker anomalo
      LET rtbroker = SELECT
          System.TimeCreated.SystemTime AS Timestamp,
          "RuntimeBroker_Anomalous_Parent" AS SigmaRule,
          "high" AS Level,
          EventData.Image AS Image,
          EventData.ParentImage AS CommandLine,
          EventData.User AS User,
          System.Computer AS Computer
        FROM events
        WHERE System.EventID.Value = 1
          AND EventData.Image =~ "(?i)RuntimeBroker\\.exe$"
          AND NOT EventData.ParentImage =~ "(?i)(svchost|services|wininit)\\.exe$"

      -- C2 connessioni
      LET c2_net = SELECT
          System.TimeCreated.SystemTime AS Timestamp,
          "C2_Network_Connection" AS SigmaRule,
          "critical" AS Level,
          EventData.Image AS Image,
          EventData.DestinationIp + ":" + EventData.DestinationPort AS CommandLine,
          EventData.User AS User,
          System.Computer AS Computer
        FROM events
        WHERE System.EventID.Value = 3
          AND (EventData.DestinationIp = "192.168.56.60"
               OR EventData.DestinationIp = "10.0.2.15")

      -- LSASS access sospetto
      LET lsass = SELECT
          System.TimeCreated.SystemTime AS Timestamp,
          "LSASS_Suspicious_Access" AS SigmaRule,
          "high" AS Level,
          EventData.SourceImage AS Image,
          EventData.GrantedAccess AS CommandLine,
          EventData.TargetImage AS User,
          System.Computer AS Computer
        FROM events
        WHERE System.EventID.Value = 10
          AND EventData.TargetImage =~ "(?i)lsass\\.exe$"
          AND EventData.GrantedAccess =~ "(0x1fffff|0x143a|0x1438|0x1010)"
          AND NOT EventData.SourceImage =~ "(?i)(svchost|csrss|wininit|MsMpEng|VBoxService)\\.exe$"

      SELECT * FROM chain(
        a=moonsniper,
        b=rtbroker,
        c=c2_net,
        d=lsass
      )

  - name: Security_Sigma_Scan
    description: Applica Sigma rules ai log Security (Kerberos attacks)
    query: |
      LET start_time = now() - LookbackHours * 3600000000000

      LET sec_events = SELECT *
        FROM parse_evtx(
          filename=SecurityLogPath
        )
        WHERE System.TimeCreated.SystemTime > start_time

      -- Kerberoasting (TGS con RC4)
      LET kerberoast = SELECT
          System.TimeCreated.SystemTime AS Timestamp,
          "Kerberoasting_TGS_RC4" AS SigmaRule,
          "high" AS Level,
          EventData.ServiceName AS Image,
          EventData.TicketEncryptionType AS CommandLine,
          EventData.TargetUserName AS User,
          System.Computer AS Computer
        FROM sec_events
        WHERE System.EventID.Value = 4769
          AND EventData.TicketEncryptionType = "0x17"
          AND EventData.Status = "0x0"
          AND NOT EventData.ServiceName =~ "\\$$"

      -- DCSync (replication rights)
      LET dcsync = SELECT
          System.TimeCreated.SystemTime AS Timestamp,
          "DCSync_Replication_Request" AS SigmaRule,
          "critical" AS Level,
          EventData.SubjectUserName AS Image,
          EventData.Properties AS CommandLine,
          EventData.SubjectUserName AS User,
          System.Computer AS Computer
        FROM sec_events
        WHERE System.EventID.Value = 4662
          AND (EventData.Properties =~ "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
               OR EventData.Properties =~ "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
          AND NOT EventData.SubjectUserName =~ "(?i)(STOHESS|WALLROSE|LIBERIO)\\$"

      -- AS-REP Roasting
      LET asrep = SELECT
          System.TimeCreated.SystemTime AS Timestamp,
          "ASREP_Roasting" AS SigmaRule,
          "high" AS Level,
          EventData.TargetUserName AS Image,
          EventData.TicketEncryptionType AS CommandLine,
          EventData.TargetUserName AS User,
          System.Computer AS Computer
        FROM sec_events
        WHERE System.EventID.Value = 4768
          AND EventData.PreAuthType = "0"
          AND EventData.TicketEncryptionType = "0x17"
          AND NOT EventData.TargetUserName =~ "\\$$"

      -- Golden Ticket (TGT con RC4)
      LET golden = SELECT
          System.TimeCreated.SystemTime AS Timestamp,
          "Golden_Ticket_RC4_TGT" AS SigmaRule,
          "high" AS Level,
          EventData.TargetUserName AS Image,
          EventData.TicketEncryptionType AS CommandLine,
          EventData.TargetUserName AS User,
          System.Computer AS Computer
        FROM sec_events
        WHERE System.EventID.Value = 4768
          AND EventData.TicketEncryptionType = "0x17"

      SELECT * FROM chain(
        a=kerberoast,
        b=dcsync,
        c=asrep,
        d=golden
      )
```

---

## 6. Riepilogo architettura

```
                        ┌─────────────────────┐
                        │   Sigma Rules (.yml) │
                        │   Formato universale │
                        └──────┬──────┬───────┘
                               │      │
            ┌──────────────────┘      └──────────────────┐
            ▼                                            ▼
   ┌─────────────────┐                        ┌──────────────────┐
   │  sigma-cli       │                        │  Manuale / VQL   │
   │  convert → Wazuh │                        │  Velociraptor    │
   └────────┬────────┘                        └────────┬─────────┘
            ▼                                          ▼
   ┌─────────────────┐                        ┌──────────────────┐
   │  /var/ossec/etc/ │                        │  Hunt / Artifact │
   │  rules/*.xml     │                        │  su tutti client │
   │  Wazuh Manager   │                        │  Velociraptor    │
   │  192.168.56.51   │                        │  192.168.56.53   │
   └─────────────────┘                        └──────────────────┘

                        ┌─────────────────────┐
                        │  YARA Rules (.yar)   │
                        │  Pattern matching    │
                        └──────┬──────┬───────┘
                               │      │
            ┌──────────────────┘      └──────────────────┐
            ▼                                            ▼
   ┌─────────────────┐                        ┌──────────────────┐
   │  yara64.exe      │                        │  yara() plugin   │
   │  Scansione       │                        │  VQL Velociraptor│
   │  manuale su host │                        │  Disco + Memoria │
   └─────────────────┘                        └──────────────────┘

   ┌──────────────────────────────────────────────────────────────┐
   │                    ELK (192.168.56.50:5601)                  │
   │  Sigma → KQL queries in Kibana Detection Rules              │
   │  Dashboard per visualizzazione alert Wazuh + Sysmon          │
   └──────────────────────────────────────────────────────────────┘
```

### File prodotti e dove vanno

| File | Destinazione | Utilizzo |
|---|---|---|
| `ad_attack_rules.yar` | Velociraptor (parametro YaraRules) oppure endpoint (yara64.exe) | Scansione disco/memoria |
| `sigma_moonsniper.yml` | sigma-cli → Wazuh XML / KQL / VQL | Detection MoonSniper |
| `sigma_zerologon_dcsync_kerberoast.yml` | sigma-cli → Wazuh XML / KQL / VQL | Detection Zerologon, DCSync, Kerberoast |
| `sigma_golden_asrep_bloodhound_lsass.yml` | sigma-cli → Wazuh XML / KQL / VQL | Detection Golden Ticket, ASREP, BloodHound, LSASS |
| `wazuh_moonsniper_rules.xml` | `/var/ossec/etc/rules/` su Wazuh Manager | Alert real-time MoonSniper |
| `velociraptor_moonsniper_eradication.yaml` | Velociraptor → Hunt | Contenimento ed eradicazione |
