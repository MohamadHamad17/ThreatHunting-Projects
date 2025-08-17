# Data Exfiltration via ZIP Archives

This document summarizes the threat hunting investigation conducted on the VM **VMName**, where suspicious archiving and exfiltration activity was identified. The investigation focused on detecting file staging, process execution, and outbound connections linked to potential data theft.  

<img width="777" height="437" alt="Screenshot 2025-08-16 at 9 40 25 PM" src="https://github.com/user-attachments/assets/c2d9a8c2-764b-4c40-b9e7-cece1568219f" />

---

## 2. Data Collection  

The initial step was to search for ZIP file activity and then pivot into process and network logs around those timestamps.  

Relevant tables:  
- DeviceFileEvents  
- DeviceProcessEvents  
- DeviceNetworkEvents  

---

### Findings  

I did a search within **MDE DeviceFileEvents** for any activities with ZIP files, and found a lot of regular activity of archiving stuff and moving to a “backup” folder:  

```kql
DeviceFileEvents  
| where DeviceName == "windows-target-1"  
| where FileName endswith ".zip"  
| order by Timestamp desc  
```
<img width="712" height="256" alt="Screenshot 2025-08-16 at 9 36 08 PM" src="https://github.com/user-attachments/assets/7713e9d0-eb0b-487c-b819-62a8cfcd947c" />

---

I took one of the instances of a ZIP file being created, noted the timestamp, and searched **DeviceProcessEvents** for any activity 1 minute before and after. Around that same time, I found that a PowerShell script was used to silently install 7-Zip, and then 7z.exe was run to archive employee data into a ZIP file.  
```kql
let specificTime = datetime(2025-07-08T08:50:08.6679932Z);  
let VMName = "windows-target-1";  
DeviceProcessEvents  
| where DeviceName == VMName  
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))  
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName, FolderPath  
| order by Timestamp desc
```
<img width="712" height="264" alt="Screenshot 2025-08-16 at 9 37 27 PM" src="https://github.com/user-attachments/assets/32fe5a32-890b-456c-a6d2-f31e42b11ed2" />


---

I reviewed the **DeviceNetworkEvents** for windows-target-1 within one minute before and after the ZIP file was created. I found a successful outbound HTTPS connection to IP **20.60.181.193** on port 443. This connection was initiated by powershell.exe, the same process that executed the **exfiltratedata.ps1** script. The IP is tied to a Microsoft Azure Blob Storage domain, confirming that the script likely exfiltrated data to a cloud-hosted endpoint.  

```kql
let specificTime = datetime(2025-07-08T08:50:08.6679932Z);  
let VMName = "windows-target-1";  
DeviceNetworkEvents  
| where DeviceName == VMName  
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))  
```
<img width="774" height="274" alt="Screenshot 2025-08-16 at 9 37 55 PM" src="https://github.com/user-attachments/assets/1173bcd7-dc44-4051-a9f6-f037bcb87253" />


---

## 4. Investigation  

The investigation confirmed the following sequence of activity:  
1. A PowerShell script (**exfiltratedata.ps1**) was executed.  
2. PowerShell silently installed **7-Zip**.  
3. **7z.exe** was then run to archive employee data into a ZIP file.  
4. Powershell.exe initiated an **outbound HTTPS connection** to an Azure Blob Storage endpoint.  

This sequence confirms that sensitive employee data was **likely exfiltrated**.  

---

## 5. Response  


Response: I relayed the information to the employee's manager, including details of the PowerShell script execution, the manual archiving of employee data using 7-Zip, and the outbound HTTPS connection to an Azure Blob Storage endpoint. This activity confirms that data was likely exfiltrated. Standing by for further instructions from management.  

To mitigate the confirmed threat, the affected device (**VMName**) should be immediately isolated to prevent any further data exfiltration. The user account responsible for executing the PowerShell script and archiving sensitive employee data should be suspended, and forensic evidence—including the ZIP file, exfiltration script, and related logs—should be preserved. Security teams should review other endpoints for similar behavior and implement detection rules for unauthorized scripting, ZIP creation in non-standard directories, and outbound connections to unapproved cloud storage services. The incident has been escalated, and we are standing by for further instructions from management or the incident response team.  

(FOR PROJECT ON GITHUB SHOW A DETECTION RULE EXAMPLE FOR ISOLATING DEVICES LIKE THIS)  

---

## 6. Documentation  

**Summary of Findings:**  
- Multiple ZIP files were created and moved to a “backup” folder.  
- PowerShell installed **7-Zip** silently and used it to archive employee data.  
- Powershell.exe made an **outbound HTTPS connection** to **20.60.181.193 (Azure Blob Storage)**.  
- Activity confirms that **data was likely exfiltrated**.  

---

## 7. Improvement  

**Improvements Suggested:**  
- Restrict PowerShell execution policies and enforce logging.  
- Limit installation of archiving utilities like 7-Zip to admin-approved channels.  
- Implement DLP (Data Loss Prevention) rules for ZIP file creation and cloud storage uploads.  
- Strengthen monitoring for unusual combinations of file, process, and network events.  

---

## MITRE ATT&CK TTPs  

- **T1059.001 – Command and Scripting Interpreter: PowerShell**  
  - PowerShell was used to silently install 7-Zip and create ZIP archives.  
- **T1071.001 – Application Layer Protocol: Web Traffic**  
  - Outbound HTTPS connection to cloud storage endpoint.  
- **T1560.001 – Archive Collected Data: Archive via Utility**  
  - 7-Zip was used to compress sensitive data before exfiltration.  
- **T1070.004 – Indicator Removal on Host: File Deletion**  
  - Archiving and moving files may indicate staging and cleanup.  
- **T1105 – Ingress Tool Transfer**  
  - 7-Zip was silently installed to support exfiltration activity.  
- **T1055.011 – Process Injection: Extra Window Memory Injection**  
  - While not directly observed, silent PowerShell operations can involve memory injection.  
- **T1027 – Obfuscated Files or Information**  
  - Use of scripts and archiving utilities helped disguise activity.  
- **T1047 – Windows Management Instrumentation**  
  - Often leveraged in silent script executions, possibly applicable here.  

---

