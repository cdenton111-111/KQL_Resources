# MITRE ATT&CK to KQL Mapping

Starter mapping of common MITRE ATT&CK techniques to Microsoft Sentinel and Defender XDR hunting ideas.

> These are starter detections. Tune thresholds, exclusions, and time windows for your environment.

## T1059 - Command and Scripting Interpreter

### Suspicious PowerShell

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "EncodedCommand", "IEX", "DownloadString", "FromBase64String", "Invoke-WebRequest")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

## T1053 - Scheduled Task/Job

### Scheduled task creation

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/create", "-create")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```

## T1060 / T1547 - Registry Run Keys or Startup Folder

### Registry run key persistence

```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("CurrentVersion\\Run", "CurrentVersion\\RunOnce")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData
```

## T1105 - Ingress Tool Transfer

### PowerShell download activity

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe")
| where ProcessCommandLine has_any ("http", "https", "DownloadFile", "DownloadString", "urlcache", "transfer")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

## T1071 - Application Layer Protocol

### Suspicious process network connections

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
```

## T1027 - Obfuscated Files or Information

### Encoded command-line patterns

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("FromBase64String", "EncodedCommand", "-enc", "-e ", "base64")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

## T1003 - OS Credential Dumping

### Credential dumping tools and LSASS access indicators

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("procdump.exe", "rundll32.exe", "comsvcs.dll", "mimikatz.exe")
   or ProcessCommandLine has_any ("lsass", "sekurlsa", "minidump", "comsvcs.dll")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

## T1087 - Account Discovery

### Account discovery commands

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("net user", "net group", "whoami", "dsquery", "Get-ADUser", "Get-ADGroup")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

## T1018 - Remote System Discovery

### Remote system discovery commands

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("net view", "nltest", "ping -n", "nslookup", "Test-Connection", "Get-ADComputer")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

## T1021 - Remote Services

### Remote service tooling

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe", "wmic.exe", "mstsc.exe", "sc.exe", "powershell.exe")
| where ProcessCommandLine has_any ("\\\\", "process call create", "New-PSSession", "Enter-PSSession", "create")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

## T1562 - Impair Defenses

### Defender or security tooling tampering

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("Set-MpPreference", "DisableRealtimeMonitoring", "Add-MpPreference", "Remove-MpPreference", "sc stop", "taskkill")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
```

## T1110 - Brute Force

### Repeated failed sign-ins

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize FailedAttempts=count() by UserPrincipalName, IPAddress, AppDisplayName
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

## T1098 - Account Manipulation

### Privileged role changes

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("Add member to role", "Add eligible member to role", "Update user", "Reset password")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
```

## T1114 - Email Collection

### Mailbox rule forwarding

```kql
OfficeActivity
| where TimeGenerated > ago(14d)
| where Workload =~ "Exchange"
| where Operation in~ ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
```

## T1567 - Exfiltration Over Web Service

### Large SharePoint or OneDrive downloads

```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where Workload in~ ("SharePoint", "OneDrive")
| where Operation =~ "FileDownloaded"
| summarize Downloads=count() by UserId, ClientIP, bin(TimeGenerated, 1h)
| where Downloads > 100
| order by Downloads desc
```
