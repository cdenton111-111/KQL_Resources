# KQL Interview Questions and Answers

Use these to prepare for SOC analyst, Microsoft Sentinel, Defender XDR, and cloud security interviews.

## 1. What is KQL?

KQL, or Kusto Query Language, is a read-only query language used to analyze structured, semi-structured, and time-series data in platforms such as Azure Data Explorer, Azure Monitor, Log Analytics, Microsoft Sentinel, and Microsoft Defender XDR Advanced Hunting.

## 2. Where is KQL used in Microsoft security?

KQL is commonly used in:

- Microsoft Sentinel analytics rules
- Microsoft Sentinel hunting queries
- Microsoft Sentinel workbooks
- Log Analytics
- Defender XDR Advanced Hunting
- Defender for Endpoint investigation
- Defender for Cloud Apps hunting
- Microsoft Entra sign-in and audit log analysis

## 3. What is the purpose of `where`?

`where` filters rows based on a condition.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
```

## 4. What is the purpose of `project`?

`project` selects the columns you want to display.

```kql
SigninLogs
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName
```

## 5. What is the purpose of `summarize`?

`summarize` aggregates rows into grouped results.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| summarize FailedSignIns=count() by UserPrincipalName
```

## 6. What is the difference between `contains` and `has`?

- `contains` searches for a substring.
- `has` searches for a full term and is usually more efficient.

```kql
DeviceProcessEvents
| where ProcessCommandLine has "EncodedCommand"
```

## 7. What does `ago()` do?

`ago()` creates a relative time filter from the current time.

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
```

## 8. What is `bin()` used for?

`bin()` groups time or numeric values into intervals.

```kql
SigninLogs
| summarize Count=count() by bin(TimeGenerated, 1h)
```

## 9. What is `let` used for?

`let` defines a reusable variable or subquery.

```kql
let Lookback = 7d;
SigninLogs
| where TimeGenerated > ago(Lookback)
```

## 10. How would you find repeated failed sign-ins?

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize FailedAttempts=count() by UserPrincipalName, IPAddress
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

## 11. How would you find successful sign-ins after repeated failures?

```kql
let Failures = SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize FailedCount=count(), LastFailure=max(TimeGenerated) by UserPrincipalName, IPAddress
| where FailedCount >= 10;
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| join kind=inner Failures on UserPrincipalName, IPAddress
| where TimeGenerated > LastFailure
| project TimeGenerated, UserPrincipalName, IPAddress, FailedCount, LastFailure, AppDisplayName
```

## 12. How would you detect suspicious PowerShell?

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "EncodedCommand", "DownloadString", "IEX", "FromBase64String")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```

## 13. How would you detect new inbox forwarding rules?

```kql
OfficeActivity
| where TimeGenerated > ago(14d)
| where Workload =~ "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
```

## 14. What is a KQL join?

A join combines rows from two tables based on a matching key.

```kql
AlertInfo
| join kind=inner AlertEvidence on AlertId
```

## 15. What are common join types?

- `inner`
- `leftouter`
- `rightouter`
- `fullouter`
- `leftanti`
- `leftsemi`

## 16. How do you reduce false positives in KQL detections?

Common tuning methods include:

- Add allowlists or watchlists
- Increase thresholds
- Add exclusions for service accounts
- Filter known management tools
- Add time-of-day logic
- Group by account, device, IP, or application
- Compare against baseline activity

## 17. How would you explain a hunting query in an interview?

A good answer includes:

1. What behavior the query detects
2. What data source it uses
3. Why the behavior is suspicious
4. What fields help with investigation
5. How you would tune it
6. What response action you would take

## 18. What is the difference between hunting and analytics rules?

- Hunting queries are usually exploratory and manually run by analysts.
- Analytics rules are scheduled detections that generate alerts or incidents.

## 19. What is a Sentinel workbook?

A workbook is a dashboard-style visualization tool in Microsoft Sentinel and Azure Monitor. Workbooks use KQL to create charts, tables, KPIs, and investigation views.

## 20. What is a good KQL troubleshooting approach?

1. Start with a small time range.
2. Confirm the table has data.
3. Use `take 10` to inspect columns.
4. Add filters one at a time.
5. Use `project` to simplify output.
6. Validate field names and data types.
7. Tune thresholds after reviewing baseline activity.
