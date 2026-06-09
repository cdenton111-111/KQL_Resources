# KQL Resources

A curated collection of Kusto Query Language resources for Microsoft Sentinel, Microsoft Defender XDR Advanced Hunting, Azure Monitor, Log Analytics, and SC-200 study.

## Official Microsoft resources

### Microsoft Kusto Query Language

- Repository: https://github.com/microsoft/Kusto-Query-Language
- Purpose: Official Microsoft Kusto Query Language repository for KQL syntax, grammar, examples, and language reference.
- Useful for: Microsoft Sentinel, Defender XDR Advanced Hunting, Azure Monitor, Log Analytics, and SC-200 study.

### Microsoft Sentinel

- Repository: https://github.com/Azure/Azure-Sentinel
- Purpose: Official Microsoft Sentinel content repository.
- Includes: Analytics rules, hunting queries, workbooks, parsers, playbooks, connectors, and solutions.

### Microsoft 365 Defender Hunting Queries

- Repository: https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries
- Purpose: Official Microsoft Defender XDR / Microsoft 365 Defender advanced hunting queries.
- Useful for: Endpoint, identity, email, cloud app, and cross-domain hunting.

### Azure Monitor Community

- Repository: https://github.com/microsoft/AzureMonitorCommunity
- Purpose: Community examples for Azure Monitor and Log Analytics queries.
- Useful for: Learning KQL beyond only security use cases.

## Learning KQL

### Must Learn KQL

- Repository: https://github.com/rod-trent/MustLearnKQL
- Purpose: Beginner-friendly KQL learning path.
- Useful for: SC-200 study, Sentinel beginners, SOC analysts, and anyone new to KQL.

### ADX in a Day

- Repository: https://github.com/Azure/ADX-in-a-Day
- Purpose: Hands-on Azure Data Explorer and KQL labs.
- Useful for: Understanding KQL fundamentals and query patterns.

## Threat hunting and detection engineering

### Hunting Queries and Detection Rules

- Repository: https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules
- Purpose: Defender, Sentinel, detection rules, hunting queries, and visualizations.
- Useful for: Practical SOC hunting and detection engineering.

### KQL Threat Hunting Queries

- Repository: https://github.com/cyb3rmik3/KQL-threat-hunting-queries
- Purpose: KQL threat hunting and detection queries for Microsoft Sentinel and Microsoft XDR.
- Useful for: Real-world hunting examples.

### Sentinel Queries

- Repository: https://github.com/reprise99/Sentinel-Queries
- Purpose: Microsoft Sentinel-focused KQL examples.
- Useful for: Threat detections, anomalies, and hunting patterns.

### LearningKijo KQL

- Repository: https://github.com/LearningKijo/KQL
- Purpose: Defender XDR hunting queries based on security blogs, cyberattacks, and practical hunting scenarios.
- Useful for: Building hunting queries from real-world attacks.

### Defender Advanced Hunting Queries

- Repository: https://github.com/francoisfried/Defender-Advanced-Hunting-Queries
- Purpose: Microsoft Defender advanced hunting queries organized around MITRE ATT&CK.
- Useful for: Mapping hunting queries to tactics and techniques.

### Advanced Hunting Queries

- Repository: https://github.com/lawndoc/AdvancedHuntingQueries
- Purpose: Microsoft 365 Advanced Hunting queries.
- Useful for: Endpoint anomalies and Defender hunting examples.

## Automation and conversion

### pySigma backend for Kusto

- Repository: https://github.com/AttackIQ/pySigma-backend-kusto
- Purpose: Converts Sigma rules into KQL for Microsoft XDR, Sentinel ASIM, and Azure Monitor.
- Useful for: Detection engineering and Sigma-to-KQL workflows.

### NL2KQL

- Repository: https://github.com/microsoft/NL2KQL
- Purpose: Natural-language-to-KQL research project.
- Useful for: Exploring AI-assisted KQL query generation.

## Recommended starting order

1. Start with `rod-trent/MustLearnKQL` to learn the basics.
2. Use `microsoft/Kusto-Query-Language` for official syntax and reference.
3. Practice with Microsoft Sentinel examples in `Azure/Azure-Sentinel`.
4. Use `microsoft/Microsoft-365-Defender-Hunting-Queries` for Defender XDR Advanced Hunting.
5. Review `Bert-JanP/Hunting-Queries-Detection-Rules` for practical SOC hunting and detection engineering.

## Core KQL topics to master

- `where`
- `project`
- `extend`
- `summarize`
- `count()` and `dcount()`
- `bin()`
- `sort by` / `order by`
- `join`
- `union`
- `let`
- `parse` / `extract`
- `make_set()` and `make_list()`
- `mv-expand`
- `ago()`
- `has`, `contains`, and `in`

## Starter query

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedLogons = count() by Account, Computer, bin(TimeGenerated, 1h)
| where FailedLogons > 10
| order by FailedLogons desc
```

This query looks for repeated failed Windows logons in the last 24 hours.
