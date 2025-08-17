
# Threat Hunt Report: Sudden Network Slowdown

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

## Scenario

The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks. All internal traffic is allowed by default, and PowerShell and other apps are unrestricted. Someone may be downloading large files or performing port scans on local hosts.

---
## Timeline Summary and Findings

windows-target-1 was found failing several connection requests.
```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount 
```
<img width="564" height="177" alt="p1" src="https://github.com/user-attachments/assets/d0f5dfba-e724-4e72-a19d-9754e5c259cf" />


After observing failed connection requests from our suspected host (10.0.0.5) in chronological order, I noticed a port scan was taking place due to the sequential order of the ports.

let IPInQuestion = "10.0.0.5";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc

<img width="659" height="360" alt="p2" src="https://github.com/user-attachments/assets/1b17a2b3-79ed-431e-9e8d-853e00fdebf8" />

I looked at the DeviceProcessEvents table to look for any suspicious activity around when the port scan started. Noticed a PowerShell script named "portscan.ps1" launch at 2025-08-15T16:37:27.6193539Z.

```kql
let VMName = "windows-target-1";
let specificTime = datetime(2025-08-15T16:38:03.7967198Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
<img width="664" height="359" alt="p3" src="https://github.com/user-attachments/assets/5d75a212-b44f-493c-bc6a-2c88d23b0c25" />


I logged into the suspect PC and observed the PowerShell script that was used to conduct the port scan.

<img width="906" height="488" alt="p4" src="https://github.com/user-attachments/assets/063e305b-0478-443b-9b72-5bb771e7346b" />


---
## Response Actions:

We found that the port scan script was launched by the system account. This was not expected behavior and not setup by admins. I isolated the device and ran a malware scan. The malware scan produced no results, out of caution, we kept the device isolated and put in a ticket to have it reimaged.

<img width="748" height="594" alt="p5" src="https://github.com/user-attachments/assets/7d49e016-4dfd-4b8c-a25c-7a0451f38c05" />

---
Relevant MITRE ATT&CK TTPs:

- T1046: Network Service Scanning
- T1086: PowerShell
- T1059.001: Command and Scripting Interpreter: PowerShell
- T1068: Exploitation for Privilege Escalation
  
