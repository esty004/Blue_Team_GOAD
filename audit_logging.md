# Configurazione di Audit e Logging su Windows per rilevare DCSync e attività PowerShell

## 1. Audit Policy

### 1.1 Account Logon

Naviga in:
`Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Account Logon`

* **Audit Kerberos Authentication Service**: Success and Failure
* **Audit Kerberos Service Ticket Operations**: Success and Failure

### 1.2 DS Access

Naviga in:
`Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > DS Access`

* **Audit Directory Service Access**: Success and Failure
* **Audit Directory Service Changes**: Success and Failure

> **Nota:** Per rilevare DCSync, è necessario configurare anche i **SACL** sugli oggetti Active Directory.

#### Configurazione SACL tramite ADSI Edit

1. Apri **ADSI Edit** (`adsiedit.msc`)
2. Click destro su **ADSI Edit (nodo radice)** → **Connect to...**
3. Configura la connessione:

   * **Name**: Default o un nome a scelta (es. `Domain NC`)
   * **Connection Point**: `Select a well known Naming Context` → `Default naming context`
   * **Computer**: `Select or type a domain or server` → inserisci il nome del DC (es. `DC01.lab.local`)
4. Click **OK**
5. Espandi il contesto del dominio per applicare i SACL agli oggetti necessari

### 1.3 Detailed Tracking

Naviga in:
`Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Detailed Tracking`

* **Audit Process Creation**: Success and Failure

---

## 2. Include Command Line in Process Creation Events

Naviga in:
`Computer Configuration > Policies > Administrative Templates > System > Audit Process Creation`

* **Include command line in process creation events**: **Enabled**

---

## 3. PowerShell Logging

### 3.1 Script Block Logging

Naviga in:
`Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell`

* **Turn on PowerShell Script Block Logging**: **Enabled**

### 3.2 Module Logging

* **Turn on Module Logging**: **Enabled**

  * Clicca **Show** e aggiungi `*` per loggare tutti i moduli

### 3.3 PowerShell Transcription

* **Turn on PowerShell Transcription**: **Enabled**
