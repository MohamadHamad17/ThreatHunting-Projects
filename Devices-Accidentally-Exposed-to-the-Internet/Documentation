# Devices Accidentally Exposed to the Internet: windows-target-1

This document summarizes the threat hunting investigation conducted on the VM **windows-target-1**, which was mistakenly exposed to the public internet. The investigation focused on identifying brute force activity, validating successful logins, and confirming whether any unauthorized access occurred.

---

## 1. Preparation

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.  


During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts.  

---

## 2. Data Collection

Consider inspecting the logs to see which devices have been exposed to the internet and have received excessive failed login attempts. Take note of the source IP addresses and number of failures, etc.  

Ensure the relevant tables contain recent logs:  
- DeviceInfo  
- DeviceLogonEvents  

---

## 3. Data Analysis

Goal: Analyze data to test your hypothesis.  

Is there any evidence of brute force success (many failed logins followed by a success?) on your VM or ANY VMs in the environment?  

If so, what else happened on that machine around the same time? Were any bad actors able to log in?  

---

### Findings

windows-target-1 has been internet facing for several days:
```kql
DeviceInfo  
| where DeviceName == "windows-target-1"  
| where IsInternetFacing == 1  
| order by Timestamp desc  
| project Timestamp, DeviceName, PublicIP, OSPlatform, IsInternetFacing  
```
Last internet facing time: **2025-07-11T00:19:47.7079524Z**  

---

Several bad actors have been attempting to log into the target machine:
```kql
DeviceLogonEvents  
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")  
| where ActionType == "LogonFailed"  
| where isnotempty(RemoteIP)  
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName  
| order by Attempts  
```
<img width="639" height="330" alt="Screenshot 2025-08-16 at 3 39 08 PM" src="https://github.com/user-attachments/assets/9e7b8402-41fc-47bf-a564-92a45b028fe5" />


---

The top 5 most failed logon attempts have not been able to successfully login:
```kql
let RemoteIPsInQuestion = dynamic(["185.224.3.219","10.0.0.8","111.67.194.32","185.224.3.219","83.222.191.62","45.41.204.12","192.109.240.116"]);  
DeviceLogonEvents  
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")  
| where ActionType == "LogonSuccess"  
| where RemoteIP has_any(RemoteIPsInQuestion)  
```

---

The only successful remote/network logons in the last 30 days was for the ‘labuser’ account (57 total):
```kql
DeviceLogonEvents  
| where DeviceName == "windows-target-1"  
| where LogonType == "Network"  
| where ActionType == "LogonSuccess"  
| where AccountName == "labuser"  
| summarize count()  
```
---

There were zero (0) failed logons for the ‘labuser’ account, indicating that a brute force attempt for this account didn’t take place, and a 1-time password guess is unlikely.
```kql
DeviceLogonEvents  
| where DeviceName == "windows-target-1"  
| where LogonType == "Network"  
| where ActionType == "LogonFailed"  
| where AccountName == "labuser"  
| summarize count()  
```
---

We checked all of the successful login IP addresses for the ‘labuser’ account to see if any of them were unusual or from an unexpected location. All were normal.

```kql
DeviceLogonEvents  
| where DeviceName == "windows-target-1"  
| where LogonType == "Network"  
| where ActionType == "LogonSuccess"  
| where AccountName == "labuser"  
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```
<img width="554" height="238" alt="Screenshot 2025-08-16 at 3 40 15 PM" src="https://github.com/user-attachments/assets/774e68b1-3165-434c-b7c0-0eb607d914f4" />

---

Though the device has been exposed to the internet and clear brute force attempts have taken place, there is no evidence of any brute force success or unauthorized access from legitimate account “labuser”.

---

## 4. Investigation

Goal: Investigate any suspicious findings.   

**Relevant MITRE ATT&CK TTPs:**  
- **T1133: External Remote Services** (VM exposed to internet via RDP or other services)  
- **T1078: Valid Accounts** (legitimate successful logons by ‘labuser’)  
- **T1110: Brute Force** (failed logon attempts from multiple public IPs)  
- **T1021: Remote Services** (successful network logons over SMB/WinRM)  

---

## 5. Response

Goal: Mitigate any confirmed threats.  


**Response Actions Taken:**  
- Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no public internet access).  
- Implemented account lockout policy.  
- Implemented MFA.  

---

## 6. Documentation

**Summary of Findings:**  
- Device was internet-facing until July 11, 2025.  
- Multiple brute force attempts were observed, none successful.  
- `labuser` was the only account to log in, with all connections from normal IPs.  
- No unauthorized access was detected.  

---

## 7. Improvement

**Improvements Suggested:**  
- Utilize a more organized KQL query structure and present findings in a clearer, structured manner.  
- Automate detection for suspicious logon patterns (failed attempts followed by a success).  
- Regular audits of NSG/firewall rules to prevent accidental exposure.  

---
