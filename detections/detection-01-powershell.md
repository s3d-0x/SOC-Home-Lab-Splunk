# Detection 01 — PowerShell Process Execution

## 1. Objective

Identify PowerShell process creation events using Sysmon telemetry collected in Splunk.

## 2. Data Source

- Log source: Sysmon
- Event ID: 1 — Process Create
- SIEM: Splunk Enterprise

## 3. SPL Query

```spl
index=* EventCode=1 Image="*\\powershell.exe"
| table _time ComputerName User ParentImage Image CommandLine IntegrityLevel
```

## 4. Investigation Procedure

1. Execute the search in Splunk.
2. Review matching events.
3. Examine the hostname, user, parent process, and command line.
4. Identify activity that needs additional investigation.
5. Record the evidence and explain the conclusion.

## 5. Evidence

Add a screenshot of the actual Splunk search results to:

`screenshots/powershell-event.png`

## 6. Limitations

This query detects matching PowerShell process creation events only when the relevant telemetry is collected and indexed. It does not detect every form of PowerShell activity and does not establish malicious intent by itself.

## 7. Validation Status

Update this section after confirming that the query returns the expected events in the lab.
