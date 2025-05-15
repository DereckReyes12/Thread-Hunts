
# Threat Event (Suspicious Use of Microsoft Edge)
**Unauthorized or Suspicious File Download via Microsoft Edge**

Reason for Threat Hunt:
Cybersecurity Directive from Management

Due to recent news and internal security concerns, management has directed a hunt for potentially unauthorized or suspicious use of Microsoft Edge to download files that may be used for malicious activity. This includes scenarios where users rename files to evade detection or open files that mimic malware (e.g., payload.exe, mimikatz.zip).

**Steps the "Bad Actor" took to Create Logs and IoCs:**
- Opened Microsoft Edge (msedge.exe)
- Visited a file-sharing website such as gofile.io
- Downloaded a fake payload file named mimikatz.zip containing payload.exe
- Extracted the .zip file and launched payload.exe
- System blocked execution and displayed the message:
"This app can’t run on your PC" — but the launch attempt created a Defender log
- File appeared in DeviceFileEvents but not in DeviceProcessEvents, indicating partial execution or block



## Tables Used to Detect IoCs:

| **Parameter**	|  **Description**|
|---------------|----------------------------------------------------------------------------------------|
| **Name**      |   DeviceFileEvents|
|**Info**       |	https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
|**Purpose**    |	Detected the file download (mimikatz.zip) and the extracted payload.exe |


| **Parameter** | **Description**|
|---------------|----------------------------------------------------------------------------------------|
|**Name**	      |   DeviceNetworkEvents|
|**Info**       | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table
|**Purpose**    |	Logged outbound connections to external IPs from msedge.exe during download

---
## Related Queries:

```kql
// File creation and zip extraction events for the payload
DeviceFileEvents
| where Timestamp > ago(1h)
| where FileName has_any("mimikatz.zip", "payload.exe")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName
```

```kql
// Outbound HTTPS connections initiated by Microsoft Edge
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where DeviceName == "dereck"
| where InitiatingProcessFileName == "msedge.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```
Created By:
Author Name: Dereck Reyes Gonzalez

Author Contact: linkedin.com/in/DereckReyes

Date: May 14, 2025

Validated By:
Reviewer Name: (To be filled by instructor/mentor)

Reviewer Contact: (Optional)

Validation Date: (Date reviewed)

**Additional Notes:**
- No malicious code was actually executed; this was a controlled lab simulation using renamed harmless files to mimic threat behavior
- payload.exe was blocked by the OS, but its file presence was still logged by Defender



