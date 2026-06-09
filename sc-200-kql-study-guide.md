# SC-200 KQL Study Guide

This guide focuses on KQL topics useful for the Microsoft SC-200: Microsoft Security Operations Analyst exam.

## Why KQL matters for SC-200

KQL is used heavily in:

- Microsoft Sentinel analytics rules
- Microsoft Sentinel hunting queries
- Microsoft Sentinel workbooks
- Log Analytics queries
- Microsoft Defender XDR Advanced Hunting
- Incident investigation and triage

## Core KQL skills to master

### Filtering

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
```

### Selecting columns

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultDescription
```

### Aggregating results

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| summarize FailedSignIns=count() by UserPrincipalName
| order by FailedSignIns desc
```

### Time binning

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| summarize Count=count() by bin(TimeGenerated, 1h)
```

### Using variables with let

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated > ago(Lookback)
| summarize Count=count() by UserPrincipalName
```

### Joining tables

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| join kind=inner SecurityIncident on $left.SystemAlertId == $right.AlertIds
```

## Sentinel tables to recognize

| Table | Purpose |
|---|---|
| `SecurityEvent` | Windows security logs |
| `SigninLogs` | Microsoft Entra ID sign-ins |
| `AuditLogs` | Entra ID audit events |
| `OfficeActivity` | Microsoft 365 audit activity |
| `SecurityAlert` | Security alerts from connected products |
| `SecurityIncident` | Microsoft Sentinel incidents |
| `Heartbeat` | Agent health and connectivity |
| `CommonSecurityLog` | Syslog/CEF security logs |
| `AzureActivity` | Azure control-plane activity |

## Defender XDR tables to recognize

| Table | Purpose |
|---|---|
| `DeviceProcessEvents` | Endpoint process activity |
| `DeviceNetworkEvents` | Endpoint network activity |
| `DeviceFileEvents` | Endpoint file activity |
| `DeviceRegistryEvents` | Endpoint registry changes |
| `DeviceLogonEvents` | Endpoint logons |
| `EmailEvents` | Email activity |
| `EmailUrlInfo` | URLs in emails |
| `UrlClickEvents` | User click activity |
| `IdentityLogonEvents` | Identity logons |
| `CloudAppEvents` | Cloud app events |
| `AlertInfo` | Alert metadata |
| `AlertEvidence` | Alert evidence |

## SC-200 query scenarios

### Failed sign-ins by user

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
| summarize FailedSignIns=count() by UserPrincipalName, AppDisplayName
| order by FailedSignIns desc
```

### Risky sign-in review

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelAggregated != "none" or RiskState != "none"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, RiskLevelAggregated, RiskState, ResultDescription
| order by TimeGenerated desc
```

### Conditional Access failures

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ConditionalAccessStatus =~ "failure"
| summarize Count=count() by UserPrincipalName, AppDisplayName, IPAddress, ResultDescription
| order by Count desc
```

### Privileged role changes

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("Add member to role", "Remove member from role", "Add eligible member to role")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc
```

### High severity Sentinel alerts

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertSeverity in~ ("High", "Critical")
| summarize Count=count() by AlertName, AlertSeverity, ProductName
| order by Count desc
```

### Recent incidents

```kql
SecurityIncident
| where TimeGenerated > ago(7d)
| project TimeGenerated, Title, Severity, Status, Owner, Classification
| order by TimeGenerated desc
```

### Suspicious PowerShell

```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d) or Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "EncodedCommand", "DownloadString", "IEX", "FromBase64String")
| project TimeGenerated, Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp desc
```

## Exam tips

- Know the difference between Sentinel and Defender XDR hunting table names.
- Practice `summarize`, `join`, `let`, `bin`, `project`, and `extend`.
- Understand how to create analytics rules from queries.
- Understand how to use workbooks for visualization.
- Understand incident investigation flow: alert, entity, timeline, evidence, response.
- Practice query tuning to reduce false positives.

## Recommended study flow

1. Learn basic KQL syntax.
2. Practice with sign-in and audit log queries.
3. Practice Sentinel hunting queries.
4. Practice Defender XDR Advanced Hunting queries.
5. Turn hunting queries into analytic-rule logic.
6. Review incident investigation scenarios.
7. Practice explaining what a query detects and how to tune it.
