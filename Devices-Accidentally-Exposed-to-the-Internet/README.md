# Devices Accidentally Exposed to the Internet: windows-target-1

<img width="825" height="489" alt="Screenshot 2025-08-16 at 4 31 24 PM" src="https://github.com/user-attachments/assets/88ab5751-b567-45ef-bd56-97f58afc8372" />


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

The device windows-target-1 was identified as being internet-facing for an extended period of time. By reviewing the DeviceInfo logs, we confirmed that the VM had its network interface exposed directly to the public internet. This status was verified by filtering for instances where the IsInternetFacing property was set to 1. The results showed multiple entries confirming exposure, ordered by timestamp to identify the most recent occurrence.

The last recorded time that windows-target-1 was internet-facing was on  **2025-08-16T20:07:13.7923551Z**  . This indicates that the VM remained publicly accessible up until that point, leaving it susceptible to external scanning, brute force attempts, or other malicious activity originating from the open internet.

```kql
DeviceInfo  
| where DeviceName == "windows-target-1"  
| where IsInternetFacing == 1  
| order by Timestamp desc  
| project Timestamp, DeviceName, PublicIP, OSPlatform, IsInternetFacing  
```
<img width="1026" height="248" alt="Screenshot 2025-08-16 at 4 35 19 PM" src="https://github.com/user-attachments/assets/78e1906e-c13e-4d0a-9e8c-84bd584058fa" />

---

Analysis of the DeviceLogonEvents showed that several external IP addresses attempted to log into windows-target-1. By focusing on failed logon types such as Network, Interactive, and RemoteInteractive, we identified repeated failed attempts tied to remote sources. The results indicate that multiple bad actors tried to authenticate against the device while it was exposed to the internet.

```kql
DeviceLogonEvents  
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")  
| where ActionType == "LogonFailed"  
| where isnotempty(RemoteIP)  
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName  
| order by Attempts  
```
<img width="1038" height="341" alt="Screenshot 2025-08-16 at 4 34 22 PM" src="https://github.com/user-attachments/assets/9cbd1f46-dae5-4aec-ac95-b019d4526c4a" />

---

The analysis of the top five IP addresses responsible for the highest number of failed logon attempts showed that none of them were able to successfully authenticate. Despite repeated efforts, every attempt from these sources resulted in failure, confirming that brute force activity did not lead to unauthorized access.

```kql
let RemoteIPsInQuestion = dynamic(["185.224.3.219","10.0.0.8","111.67.194.32","185.224.3.219","83.222.191.62","45.41.204.12","192.109.240.116"]);  
DeviceLogonEvents  
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")  
| where ActionType == "LogonSuccess"  
| where RemoteIP has_any(RemoteIPsInQuestion)
```
<img width="1032" height="391" alt="Screenshot 2025-08-16 at 4 37 44 PM" src="https://github.com/user-attachments/assets/3eb53a91-efee-4793-a6b9-011145774631" />

---

Within the last 30 days, the only successful remote or network logons recorded on windows-target-1 were tied to the labuser account. In total, there were 7 successful logons, all of which were legitimate. No other accounts showed signs of successful authentication, further confirming that attackers were not able to gain unauthorized access.

```kql
DeviceLogonEvents  
| where DeviceName == "windows-target-1"  
| where LogonType == "Network"  
| where ActionType == "LogonSuccess"  
| where AccountName == "labuser"  
| summarize count()  
```
<img width="1032" height="391" alt="Screenshot 2025-08-16 at 4 44 41 PM" src="https://github.com/user-attachments/assets/215948ad-6b56-4524-8ba7-920d75d03cb8" />

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
<img width="1032" height="391" alt="Screenshot 2025-08-16 at 4 47 29 PM" src="https://github.com/user-attachments/assets/f0e982fc-77ef-4658-afec-1218151a2ed1" />

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
<img width="1032" height="391" alt="Screenshot 2025-08-16 at 4 48 00 PM" src="https://github.com/user-attachments/assets/1c6d5516-a2a4-4a0d-af2c-8c5eff5fca8f" />

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
- Device was internet-facing until 2025-08-16T20:07:13.7923551Z. 
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
