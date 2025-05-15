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
| where DeviceName == "dereck"
```

![payload](https://github.com/user-attachments/assets/0ac0f596-90e0-44f3-8c2e-5825dcca6569)

  - `mimikatz.zip` was created in the Downloads directory

  - `payload.exe` was extracted and logged by Defender, confirming file-level telemetry

## 2. Searched the `DeviceNetworkEvents` Table for Edge Connections
Edge (`msedge.exe`) was observed making HTTPS connections shortly before the file download.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where DeviceName == "dereck"
| where InitiatingProcessFileName == "msedge.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

![network](https://github.com/user-attachments/assets/2bd10201-38b6-4b3d-a4ea-cfc43a5243f6)

**Findings:**

Multiple outbound connections from `msedge.exe` over port 443 to external IPs

Suggests browsing or download activity occurred using `Microsoft Edge`

3. Attempted to Capture Process Execution via DeviceProcessEvents
While the payload.exe file was launched, the system displayed an error:
“This app can’t run on your PC” — indicating an execution attempt that failed

No matching results were returned by:'
```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName == "payload.exe"
```
![no results](https://github.com/user-attachments/assets/e2dcdc35-acc1-41e3-9b9f-722647c08e46)


**Conclusion:**
The attempt to run the file likely triggered DeviceFileEvents but failed early enough to avoid full DeviceProcessEvents logging.


**Chronological Event Timeline**

- **1. File Download - Suspicious Archive**
  Timestamp: 2025-05-14T00:24:00Z (approx.)

  Event: mimikatz.zip downloaded to the system using Microsoft Edge

  Action: File creation detected

  Path: C:\Users\dereck\Downloads\mimikatz.zip

- **2. File Extraction - Payload Delivered**
  Timestamp: 2025-05-14T00:25:00Z (approx.)

  Event: Archive extracted, payload.exe appeared in Documents\hacking-tools

  Action: File creation detected

  Path: C:\Users\dereck\Documents\hacking-tools\payload.exe

- **3. File Execution Attempt - Payload**
  Timestamp: 2025-05-14T00:26:00Z (approx.)

  Event: User attempted to execute payload.exe

  Action: Windows blocked the app from running

  Message: “This app can’t run on your PC”

  Result: No full DeviceProcessEvents telemetry was captured, likely due to early execution block

- **4. Network Connections - Microsoft Edge**
   Timestamp Range: Between 2025-05-14T00:20:00Z and 00:25:00Z

   Event: msedge.exe initiated multiple HTTPS connections on port 443

   IPs: Included external destinations, indicating browsing or download activity

  **Summary**

  A user on the device dereck used Microsoft Edge to access a public file-sharing service and download an archive named mimikatz.zip. The ZIP file contained a renamed .exe (payload.exe) that mimicked a known hacking tool. The file was extracted and launched, 
  triggering a system alert but failing to fully execute.

  The telemetry confirms file creation, execution attempt, and associated network activity. While the file did not successfully run, the attempt represents a policy violation and threat emulation scenario worth documenting.

  Response Taken
  Activity was logged and confirmed in Microsoft Defender for Endpoint

  The machine was monitored for further suspicious activity

  Results submitted as part of threat hunting lab documentation

  No actual malware was used — all files were benign simulations

  Created By:
  Author Name: Dereck Reyes Gonzalez

  Author Contact: linkedin.com/in/DereckReyes

  Date: May 14, 2025

  Validated By:
  Reviewer Name: (To be completed)

  Reviewer Contact: (Optional)

  Validation Date: (To be completed)





