# Microsoft Sentinel Hunting Queries

A starter collection of Microsoft Sentinel KQL hunting queries for SOC analysis, incident response, and SC-200 practice.

> Review and tune each query for your environment, table names, data connectors, and normal baseline activity.

## 1. Multiple failed Windows logons

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedLogons = count() by Account, Computer, IpAddress, bin(TimeGenerated, 1h)
| where FailedLogons > 10
| order by FailedLogons desc
```

## 2. Successful logon after repeated failures

```kql
let FailedLogons = SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedCount = count(), FirstFailure=min(TimeGenerated), LastFailure=max(TimeGenerated) by Account, Computer, IpAddress
| where FailedCount >= 10;
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| join kind=inner FailedLogons on Account, Computer
| where TimeGenerated > LastFailure
| project TimeGenerated, Account, Computer, IpAddress, FailedCount, FirstFailure, LastFailure
```

## 3. New local administrator added

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4728, 4732, 4756)
| where TargetAccount contains "Administrators"
| project TimeGenerated, Computer, SubjectAccount, TargetAccount, MemberName, Activity
| order by TimeGenerated desc
```

## 4. Account lockouts

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4740
| summarize Lockouts=count() by TargetAccount, Computer, bin(TimeGenerated, 1h)
| order by Lockouts desc
```

## 5. Password reset activity

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4723, 4724)
| project TimeGenerated, Computer, SubjectAccount, TargetAccount, Activity
| order by TimeGenerated desc
```

## 6. Disabled account enabled

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4722
| project TimeGenerated, Computer, SubjectAccount, TargetAccount, Activity
| order by TimeGenerated desc
```

## 7. Rare process execution

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| summarize ExecutionCount=count(), Devices=dcount(DeviceName) by FileName, FolderPath
| where ExecutionCount < 5
| order by ExecutionCount asc
```

## 8. Suspicious PowerShell activity

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "EncodedCommand", "IEX", "DownloadString", "FromBase64String", "Invoke-WebRequest")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

## 9. Suspicious command shell usage

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| summarize Count=count(), Devices=dcount(DeviceName) by FileName, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Count desc
```

## 10. External network connections from PowerShell

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

## 11. New scheduled task created

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/create", "-create")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by TimeGenerated desc
```

## 12. Registry run key persistence

```kql
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
| where RegistryKey has_any ("\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated desc
```

## 13. Suspicious file dropped in startup folder

```kql
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where FolderPath has "Startup"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256
| order by TimeGenerated desc
```

## 14. Defender malware detections

```kql
DeviceTvmSoftwareEvidenceBeta
| take 10
```

Alternative if using Defender alerts:

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where ProductName has_any ("Microsoft Defender", "Defender")
| project TimeGenerated, AlertName, Severity, CompromisedEntity, ProductName, Tactics, Techniques
| order by TimeGenerated desc
```

## 15. High severity Sentinel alerts

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertSeverity in~ ("High", "Critical")
| summarize AlertCount=count() by AlertName, AlertSeverity, ProductName
| order by AlertCount desc
```

## 16. Impossible travel-style sign-ins

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed
| order by UserPrincipalName, TimeGenerated asc
```

Use this as a starting point and enrich with UEBA, Identity Protection, or custom geo logic.

## 17. Failed MFA attempts

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where Status has_any ("MFA", "multi-factor", "authentication failed")
| summarize Count=count() by UserPrincipalName, IPAddress, AppDisplayName, ResultDescription
| order by Count desc
```

## 18. Legacy authentication attempts

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed !in~ ("Browser", "Mobile Apps and Desktop clients")
| summarize Count=count() by UserPrincipalName, ClientAppUsed, AppDisplayName, IPAddress
| order by Count desc
```

## 19. Sign-ins from risky countries

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where LocationDetails.countryOrRegion !in~ ("US", "United States")
| summarize Count=count() by UserPrincipalName, tostring(LocationDetails.countryOrRegion), IPAddress, AppDisplayName
| order by Count desc
```

## 20. New inbox forwarding rules

```kql
OfficeActivity
| where TimeGenerated > ago(14d)
| where Workload =~ "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
| order by TimeGenerated desc
```

## 21. Mailbox external forwarding setting changed

```kql
OfficeActivity
| where TimeGenerated > ago(14d)
| where Workload =~ "Exchange"
| where Operation has_any ("Set-Mailbox", "Set-TransportRule")
| where Parameters has_any ("ForwardingSmtpAddress", "DeliverToMailboxAndForward", "RedirectMessageTo")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
| order by TimeGenerated desc
```

## 22. Suspicious OAuth app consent

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("Consent", "Add service principal", "Add app role assignment")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

## 23. Privileged role assignment

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("Add member to role", "Add eligible member to role", "Add scoped member to role")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

## 24. Conditional Access failures

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ConditionalAccessStatus =~ "failure"
| summarize Count=count() by UserPrincipalName, AppDisplayName, IPAddress, ResultDescription
| order by Count desc
```

## 25. Rare user agent activity

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| summarize Count=count(), Users=dcount(UserPrincipalName) by UserAgent, AppDisplayName
| where Users <= 2
| order by Count asc
```

## 26. Mass file deletion in SharePoint or OneDrive

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Workload in~ ("SharePoint", "OneDrive")
| where Operation has_any ("FileDeleted", "FileRecycled")
| summarize DeletedFiles=count() by UserId, Site_Url, bin(TimeGenerated, 1h)
| where DeletedFiles > 50
| order by DeletedFiles desc
```

## 27. Large file download activity

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Workload in~ ("SharePoint", "OneDrive")
| where Operation =~ "FileDownloaded"
| summarize Downloads=count() by UserId, ClientIP, bin(TimeGenerated, 1h)
| where Downloads > 100
| order by Downloads desc
```

## 28. Anonymous sharing links created

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Workload in~ ("SharePoint", "OneDrive")
| where Operation has_any ("AnonymousLinkCreated", "SharingInvitationCreated")
| project TimeGenerated, UserId, Operation, Site_Url, SourceFileName, ClientIP
| order by TimeGenerated desc
```

## 29. Suspicious archive tool execution

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("7z.exe", "rar.exe", "winrar.exe", "powershell.exe")
| where ProcessCommandLine has_any (".zip", ".7z", ".rar", "Compress-Archive")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

## 30. Possible data staging directories

```kql
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where FolderPath has_any ("\\temp\\", "\\users\\public\\", "\\programdata\\")
| where FileName endswith_any (".zip", ".7z", ".rar")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256
| order by TimeGenerated desc
```
