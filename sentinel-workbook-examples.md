# Microsoft Sentinel Workbook Examples

KQL examples that can be used in Microsoft Sentinel or Azure Monitor workbooks.

## Workbook design ideas

Useful workbook sections:

1. Executive summary
2. Sign-in trends
3. Failed sign-ins
4. Conditional Access failures
5. Risky users and risky sign-ins
6. High severity alerts
7. Incident status
8. Endpoint detections
9. Email security events
10. SharePoint and OneDrive activity

## KPI: Total Sentinel incidents in the last 7 days

```kql
SecurityIncident
| where TimeGenerated > ago(7d)
| summarize TotalIncidents=count()
```

## KPI: Open incidents by severity

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| where Status !in~ ("Closed")
| summarize OpenIncidents=count() by Severity
| order by OpenIncidents desc
```

## Chart: Incidents over time

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| summarize Incidents=count() by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

## Table: Recent high severity incidents

```kql
SecurityIncident
| where TimeGenerated > ago(14d)
| where Severity in~ ("High", "Critical")
| project TimeGenerated, Title, Severity, Status, Owner, Classification
| order by TimeGenerated desc
```

## Chart: Failed sign-ins by hour

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize FailedSignIns=count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
```

## Table: Top failed sign-in users

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
| summarize FailedSignIns=count() by UserPrincipalName
| top 20 by FailedSignIns desc
```

## Table: Conditional Access failures

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ConditionalAccessStatus =~ "failure"
| summarize Failures=count() by UserPrincipalName, AppDisplayName, IPAddress, ResultDescription
| order by Failures desc
```

## Chart: Sign-ins by application

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| summarize SignIns=count() by AppDisplayName
| top 20 by SignIns desc
```

## Table: Risky sign-ins

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelAggregated != "none" or RiskState != "none"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, RiskLevelAggregated, RiskState, ResultDescription
| order by TimeGenerated desc
```

## Chart: Alerts by product

```kql
SecurityAlert
| where TimeGenerated > ago(14d)
| summarize Alerts=count() by ProductName
| order by Alerts desc
```

## Chart: Alerts by tactic

```kql
SecurityAlert
| where TimeGenerated > ago(14d)
| extend Tactic = tostring(Tactics)
| summarize Alerts=count() by Tactic
| order by Alerts desc
```

## Table: High severity alerts

```kql
SecurityAlert
| where TimeGenerated > ago(14d)
| where AlertSeverity in~ ("High", "Critical")
| project TimeGenerated, AlertName, AlertSeverity, ProductName, CompromisedEntity, Tactics, Techniques
| order by TimeGenerated desc
```

## Chart: Defender process events by device

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| summarize ProcessEvents=count() by DeviceName
| top 20 by ProcessEvents desc
```

## Table: Suspicious PowerShell events

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "EncodedCommand", "DownloadString", "IEX", "FromBase64String")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp desc
```

## Chart: Email volume by sender domain

```kql
EmailEvents
| where Timestamp > ago(7d)
| extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
| summarize EmailCount=count() by SenderDomain
| top 20 by EmailCount desc
```

## Table: Suspicious email attachments

```kql
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in~ ("exe", "js", "vbs", "scr", "iso", "img", "lnk")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256
| order by Timestamp desc
```

## Chart: SharePoint and OneDrive downloads

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Workload in~ ("SharePoint", "OneDrive")
| where Operation =~ "FileDownloaded"
| summarize Downloads=count() by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
```

## Table: Large download activity

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Workload in~ ("SharePoint", "OneDrive")
| where Operation =~ "FileDownloaded"
| summarize Downloads=count() by UserId, ClientIP, bin(TimeGenerated, 1h)
| where Downloads > 100
| order by Downloads desc
```

## Workbook tips

- Use parameters for time range, user, device, and severity.
- Start with KPI tiles for executive summaries.
- Use charts for trends and tables for investigation details.
- Add links to incidents, alerts, users, and devices when possible.
- Tune queries for the data sources connected to the workspace.
