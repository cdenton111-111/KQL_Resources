# Defender XDR Advanced Hunting Cheat Sheet

A quick reference for Microsoft Defender XDR Advanced Hunting using KQL.

## Common Defender XDR tables

| Table | Purpose |
|---|---|
| `DeviceProcessEvents` | Process creation and command-line activity |
| `DeviceFileEvents` | File creation, modification, deletion, and movement |
| `DeviceNetworkEvents` | Network connections from endpoints |
| `DeviceRegistryEvents` | Registry key and value changes |
| `DeviceLogonEvents` | Local and remote logon activity |
| `DeviceEvents` | Miscellaneous endpoint events |
| `DeviceImageLoadEvents` | DLL and image load activity |
| `EmailEvents` | Email message metadata |
| `EmailAttachmentInfo` | Email attachment metadata |
| `EmailUrlInfo` | URLs found in emails |
| `UrlClickEvents` | User URL click activity |
| `IdentityLogonEvents` | Identity sign-in and authentication events |
| `IdentityDirectoryEvents` | Directory and identity object changes |
| `CloudAppEvents` | Defender for Cloud Apps activity |
| `AlertInfo` | Alert metadata |
| `AlertEvidence` | Evidence connected to alerts |

## Basic query pattern

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

## Useful operators

| Operator | Use |
|---|---|
| `where` | Filter rows |
| `project` | Select columns |
| `extend` | Add calculated columns |
| `summarize` | Aggregate results |
| `join` | Correlate tables |
| `union` | Combine tables |
| `let` | Define reusable subqueries or variables |
| `parse` | Extract structured fields |
| `extract` | Regex extraction |
| `mv-expand` | Expand dynamic arrays |
| `order by` | Sort results |

## String matching

| Operator | Meaning |
|---|---|
| `has` | Term match, usually faster |
| `contains` | Substring match |
| `=~` | Case-insensitive equals |
| `in~` | Case-insensitive list match |
| `has_any` | Matches any term in a list |
| `endswith` | String ending match |
| `startswith` | String beginning match |

## Suspicious PowerShell

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "EncodedCommand", "DownloadString", "IEX", "FromBase64String", "Invoke-WebRequest")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## LOLBins often worth reviewing

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe", "wmic.exe")
| summarize Count=count(), Devices=dcount(DeviceName) by FileName, InitiatingProcessFileName
| order by Count desc
```

## Network connections by suspicious processes

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

## Recently seen files by hash

```kql
let TargetHash = "PUT_SHA256_HERE";
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 =~ TargetHash
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessAccountName
| order by Timestamp desc
```

## File execution by hash

```kql
let TargetHash = "PUT_SHA256_HERE";
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 =~ TargetHash
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## Rare processes

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| summarize ExecutionCount=count(), DeviceCount=dcount(DeviceName) by FileName, FolderPath
| where DeviceCount <= 2 and ExecutionCount <= 5
| order by ExecutionCount asc
```

## Process tree view

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName =~ "DEVICE_NAME_HERE"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Parent=InitiatingProcessFileName, Process=FileName, ProcessCommandLine
| order by Timestamp asc
```

## Email with malicious attachments

```kql
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in~ ("exe", "js", "vbs", "scr", "iso", "img", "lnk")
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256
| order by Timestamp desc
```

## URL clicks after email delivery

```kql
UrlClickEvents
| where Timestamp > ago(7d)
| project Timestamp, AccountUpn, Url, ActionType, Workload, IPAddress
| order by Timestamp desc
```

## Correlate email and URL click activity

```kql
EmailUrlInfo
| where Timestamp > ago(7d)
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(7d)
) on Url
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Url, AccountUpn, ActionType, IPAddress
| order by Timestamp desc
```

## Alert evidence review

```kql
AlertInfo
| where Timestamp > ago(7d)
| join kind=inner AlertEvidence on AlertId
| project Timestamp, Title, Severity, Category, EntityType, DeviceName, AccountName, FileName, SHA256, RemoteUrl, RemoteIP
| order by Timestamp desc
```

## Investigation tips

1. Start with the alert or indicator.
2. Pivot by device, account, hash, IP, URL, and process command line.
3. Expand the time window around the first observed activity.
4. Review parent and child processes.
5. Correlate endpoint, identity, email, and cloud app data.
6. Document the query, finding, and response action.
