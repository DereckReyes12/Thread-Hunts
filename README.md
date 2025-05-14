# Threat Hunt Report: Suspicious File Download via Microsoft Edge

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft Edge Browser

## Scenario
Management issued a directive to investigate potential abuse of Microsoft Edge for unauthorized file downloads. This follows a series of alerts related to suspicious outbound connections and reports of renamed executable files being used to bypass endpoint protections.
The goal was to detect any signs of Edge being used to download or execute suspicious files — including ZIPs and executables resembling known hacking tools — and assess whether users tried to execute them.

## High-Level IoC Discovery Plan
- **Check `DeviceFileEvents`** for .zip or .exe downloads initiated by msedge.exe
- **Check `DeviceProcessEvents`** for execution attempts of suspicious payloads
- **Check `DeviceNetworkEvents`** for outbound activity initiated by Edge to public file-sharing platforms

## Steps Taken
1. Searched the `DeviceFileEvents` Table
A ZIP file named mimikatz.zip and a file named payload.exe were observed, indicating download and unpacking of a suspicious archive.

**Query used to locate events:**
``` kql
DeviceFileEvents
| where Timestamp > ago(1h)
| where FileName has_any("mimikatz.zip", "payload.exe")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName
```

![payload](https://github.com/user-attachments/assets/0ac0f596-90e0-44f3-8c2e-5825dcca6569)







