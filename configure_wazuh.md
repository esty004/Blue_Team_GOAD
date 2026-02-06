## ⚙️ Configure Wazuh Agent to Collect Sysmon Logs
Now, we will configure the Wazuh agent to read **Sysmon logs** and apply the custom rules from this repository.

1. **Edit the Wazuh Agent Configuration File**:
   - Open the Wazuh agent config file (`ossec.conf`) located at:
     ```
     C:\Program Files (x86)\ossec-agent\ossec.conf
     ```
   - Add the following section inside `<localfile>` tags:
     ```xml
     <localfile>
       <location>Microsoft-Windows-Sysmon/Operational</location>
       <log_format>eventchannel</log_format>
     </localfile>
     ```

2. **Add Fine-Tuned Wazuh-Sysmon Rules for Sysmon**:
   - The wazuh has default rules for Sysmon. But for more data enrichments and visibility, 
     you can use the **.xml** file from **wazuh_sysmon-rule folder**. You can read here .[Fine-tuned_wazuh-sysmon_rule](https://github.com/esty004/Blue_Team_GOAD/blob/main/wazuh_sysmon_rule/custom_sysmon_rule.md)
   
3. **Restart Wazuh Services**:
   - Restart the Wazuh agent on Windows:
     ```powershell
     Restart-Service -Name Wazuh -Force
     ```
   - Restart the Wazuh manager to apply new rules:
     ```bash
     sudo systemctl restart wazuh-manager
     ```
