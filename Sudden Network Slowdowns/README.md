# Sudden Network Slowdowns

<img width="768" height="342" alt="Screenshot 2025-08-16 at 9 27 35 PM" src="https://github.com/user-attachments/assets/a094bfc1-5130-494d-b826-d8fa5955788d" />

This document summarizes the threat hunting investigation conducted on the VM **win-10-vm**, which experienced degraded network performance. The investigation focused on identifying whether malicious internal activity, such as port scanning, contributed to the slowdown.  

---

## 1. Preparation  

The server team noticed significant network performance degradation on older devices within the **10.0.0.0/16** range. External DDoS was ruled out, leading the security team to suspect something internal. Since local network traffic is generally unrestricted and PowerShell usage is common, it was possible that a device was either downloading large amounts of data or conducting port scanning.  

All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

---

## 2. Data Collection  


The focus was on identifying excessive failed or successful connections across devices. If suspicious behavior was found, the plan was to pivot into file and process events to validate root causes.  

Relevant tables:  
- DeviceNetworkEvents  
- DeviceFileEvents  
- DeviceProcessEvents  

---

## 3. Data Analysis  

Activity: Look for anomalies, patterns, or indicators of compromise (IOCs).  

Queries included:  
```kql
DeviceNetworkEvents  
| where ActionType == "ConnectionFailed"  
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP  
| order by FailedConnectionsAttempts desc  

let IPInQuestion = "10.0.0.5";  
DeviceNetworkEvents  
| where ActionType == "ConnectionFailed"  
| where LocalIP == IPInQuestion  
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP  
| order by FailedConnectionsAttempts desc  

let IPInQuestion = "10.0.0.5";  
DeviceNetworkEvents  
| where ActionType == "ConnectionFailed"  
| where LocalIP == IPInQuestion  
| order by Timestamp desc  

let VMName = "windows-target-1";  
let specificTime = datetime(2024-10-18T04:09:37.5180794Z);  
DeviceProcessEvents  
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))  
| where DeviceName == VMName  
| order by Timestamp desc  
| project Timestamp, FileName, InitiatingProcessCommandLine  
```
---

### Findings  

Multiple devices within the environment were observed attempting to connect to the same internal host (**10.0.0.5**) but repeatedly failing. For example, **rdadnt-ls-lab6** experienced **517 failed connection attempts**, while **windows10-vm** had **205 failures**, all targeting 10.0.0.5. These repeated failures suggested the host may have been unresponsive, overwhelmed, or targeted by scanning activity.  

```kql
DeviceNetworkEvents  
| where DeviceName == "win-10-vm"  
| where ActionType == "ConnectionFailed" or ActionType == "ConnectionSuccess"  
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP, RemoteIP  
| order by FailedConnectionsAttempts desc  
```
<img width="733" height="280" alt="Screenshot 2025-08-16 at 9 20 21 PM" src="https://github.com/user-attachments/assets/7d0d7c55-6351-4272-b442-23062dc0ec90" />

---

Further review of connection attempts from the suspected host (**10.0.0.85**) revealed that destination ports were being scanned sequentially. This included well-known ports such as 443, 465, and 587, which strongly indicated deliberate reconnaissance activity.  
```kql
let IPInQuestion = "10.0.0.85";  
DeviceNetworkEvents  
| where RemoteIP == "10.0.0.5"  
| where ActionType == "ConnectionFailed"  
| where LocalIP == IPInQuestion  
| order by Timestamp desc  
```
<img width="817" height="310" alt="Screenshot 2025-08-16 at 9 21 01 PM" src="https://github.com/user-attachments/assets/f8fbd665-1815-47c1-b641-c2f2feabae52" />

---

Pivoting into process logs, suspicious activity was confirmed. The **DeviceProcessEvents** table showed that a PowerShell script named **portscan.ps1** was executed on **2025-07-07T16:38:13.6433879Z**.  

```kql
let VMName = "r3dant-ls-lab6";  
let specificTime = datetime(2025-07-07T16:38:54.5069495Z);  
DeviceProcessEvents  
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))  
| where DeviceName == VMName  
| order by Timestamp desc  
| project Timestamp, FileName, InitiatingProcessCommandLine  
```

<img width="916" height="255" alt="Screenshot 2025-08-16 at 9 21 20 PM" src="https://github.com/user-attachments/assets/1490e8f6-472e-48de-bbd1-5203337634a8" />

---

Upon logging into the suspect computer, the file **portscan.ps1** was found, confirming it was used to execute the port scan. Further analysis showed that the script was launched by the **SYSTEM account**, which is highly unusual and not expected under normal conditions.  

The device was isolated, and a malware scan was performed. Although no malware was detected, the machine remained isolated, and a ticket was opened to have it re-imaged as a precaution.  

<img width="820" height="309" alt="Screenshot 2025-08-16 at 9 22 16 PM" src="https://github.com/user-attachments/assets/f5fc1fa9-d46a-458d-95d8-85e9e430bce2" />

<img width="817" height="287" alt="Screenshot 2025-08-16 at 9 22 50 PM" src="https://github.com/user-attachments/assets/919df96b-0fb5-4309-99de-f3641f7ec5aa" />


---

## 4. Investigation  

**Relevant MITRE ATT&CK TTPs:**  
- **TA0043: Reconnaissance** → **T1046: Network Service Scanning**  
- **TA0002: Execution** → **T1059.001: Command and Scripting Interpreter (PowerShell)**  
- **TA0004: Privilege Escalation** → **T1078.003: Valid Accounts (Local Accounts)**  
- **TA0007: Discovery** → **T1049: System Network Connections Discovery**  
- **TA0008: Lateral Movement (potential)** → **T1021: Remote Services**  

---

## 5. Response  

**Response Actions Taken:**  
- Isolated the affected device from the network.  
- Conducted a malware scan (returned clean).  
- Submitted a ticket to re-image and rebuild the machine.  
- Reviewed account and process execution logs to ensure no persistence was established.  

---

## 6. Documentation  

**Summary of Findings:**  
- Multiple devices attempted repeated failed connections to **10.0.0.5**.  
- Sequential port scanning activity confirmed from **10.0.0.85**.  
- PowerShell script **portscan.ps1** was executed under the SYSTEM account.  
- Device was isolated and scheduled for rebuild.  

---

## 7. Improvement  

**Improvements Suggested:**  
- Restrict unrestricted PowerShell usage through policy.  
- Implement monitoring for unusual process launches under privileged accounts.  
- Develop automated alerts for sequential port scanning activity.  
- Audit internal network access controls to prevent unrestricted lateral scanning.  

---
