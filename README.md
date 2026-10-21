# SOC Home Lab — Splunk SIEM

## Overview

This project documents my personal Security Operations Center (SOC) home lab, built to practice security monitoring, Windows event analysis, threat detection, and investigation using Splunk SIEM.

The goal is to understand how security events are generated on an endpoint, collected by a SIEM, and analyzed to identify potentially suspicious activity.

## Objectives

- Configure Splunk to collect and search Windows security-related events.
- Use Sysmon to monitor endpoint activity.
- Analyze process creation events and PowerShell execution.
- Develop SPL queries to identify suspicious behavior.
- Document investigation findings and potential detection improvements.

## Lab Architecture

The core lab components include:

| Component | Purpose |
|---|---|
| Splunk Enterprise | SIEM platform for searching and analyzing logs |
| Windows 10 | Endpoint generating system and security events |
| Sysmon | Endpoint telemetry, including process creation events |
| Splunk Universal Forwarder | Forwards Windows logs to Splunk |
| Attacker VM | Intended for controlled security testing |

The attacker VM and any additional infrastructure are documented as implemented only when their configuration and connectivity have been verified.

**Architecture diagram:** See `diagrams/soc-lab-architecture.png` when added.

## Tools and Technologies

- Splunk Enterprise
- Splunk Universal Forwarder
- Microsoft Sysmon
- Windows 10
- SPL (Search Processing Language)
- Virtual machines and isolated lab networking

## Detection Engineering

### Detection 01 — PowerShell Process Execution

**Objective:** Identify PowerShell process creation events in collected endpoint telemetry.

**Data source:** Sysmon Event ID 1 (Process Create).

**SPL query:**

```spl
index=* EventCode=1 Image="*\\powershell.exe"
| table _time ComputerName User ParentImage Image CommandLine IntegrityLevel
```

**Investigation focus:**

- When was the process executed?
- Which host and user account were involved?
- What process launched PowerShell?
- What command-line arguments were recorded?
- Does the activity require further investigation?

**Important:** PowerShell execution is not inherently malicious. Findings must be assessed in context before classifying activity as suspicious.

## Investigation Evidence

Evidence and investigation notes will be added as the lab develops.

Planned documentation includes:

- Splunk search results
- Relevant Windows and Sysmon events
- Detection queries and their expected behavior
- Investigation findings and limitations
- Opportunities to improve detection coverage

## Skills Demonstrated

- SIEM log analysis
- Windows endpoint telemetry
- Sysmon event investigation
- SPL query development
- Security event triage
- Technical documentation

## Future Improvements

- Develop and test additional detection rules.
- Build Splunk dashboards for endpoint monitoring.
- Investigate suspicious process execution and other attack behaviors in an isolated environment.
- Document detection validation, false positives, and investigation findings.
- Expand log sources and improve monitoring coverage.

## Disclaimer

This project is for educational and defensive cybersecurity purposes. All security testing should be conducted in an authorized, isolated lab environment.
