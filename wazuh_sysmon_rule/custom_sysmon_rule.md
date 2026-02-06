# Fine-Tuned Wazuh Sysmon Rules

This repository contains a **fine-tuned Wazuh rule file** (`0595-win-sysmon_rules.xml`) designed to enhance security monitoring and log collection for **Wazuh SIEM**. The ruleset is optimized to **reduce noise, capture high-value security events**, and improve threat detection efficiency.

## 🔹 Features & Improvements
- **Focused Event Detection**: Enhances Wazuh’s ability to detect and alert on important Sysmon events.
- **Enhanced Detection**: Captures critical security events such as process creation, network connections, registry changes, and DNS queries (**Event ID 22**).
- **Optimized for Wazuh**: Ensures better alerting and correlation with Wazuh’s built-in rules.
- **Performance Considerations**: Minimizes excessive logging to prevent storage and processing overhead.

## 📌 Key Detected Events
- **Process Execution (Event ID 1)**
- **File Creation (Event ID 11)**
- **Registry Modifications (Event ID 13-14)**
- **DNS Queries (Event ID 22)**
- **Network Connections (Event ID 3)**
- **Named Pipe Events (Event ID 17-19)**
- **WMI Activity (Event ID 19-20)**

## 📖 Installation & Usage
1. **Backup** your existing Wazuh Sysmon rule file before making changes:
   ```bash
   sudo cp /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml.bak
   ```
2. **Download and replace** the existing rule file with the updated version from this repository:
   ```bash
   wget https://raw.githubusercontent.com/esty004/Blue_Team_GOAD/main/wazuh_sysmon_rule/0595-win-sysmon_rules.xml
   sudo cp 0595-win-sysmon_rules.xml /var/ossec/ruleset/rules/
   ```
3. **Restart Wazuh Manager** to apply the new rules:
   ```bash
   sudo systemctl restart wazuh-manager
   ```
