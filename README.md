# WSLGuardian

WSLGuardian is a lightweight Python-based Windows security monitoring service created as an academic proof-of-concept for detecting suspicious activity executed through Windows Subsystem for Linux (WSL).

It monitors Windows-visible WSL processes, checks WSL process activity and recent shell history against predefined detection rules, attempts to terminate flagged sessions, and writes both readable logs and JSONL events for security review or SIEM ingestion.

## Project context

This project was developed under **NEXUS GUARD** as an Information Security university project. The goal is to demonstrate how WSL can become a monitoring blind spot in Windows environments and how a host-side lightweight monitor can provide basic visibility and response.

## Features

- Detects WSL-related processes such as `wsl.exe`, `bash.exe`, and distro launchers.
- Uses regex-based detection rules for suspicious tools and command patterns.
- Attempts multiple termination methods when a rule is matched.
- Writes normal text logs and SIEM-friendly JSONL event logs.
- Supports console/debug mode for testing.
- Supports Windows service installation through `pywin32`.

## Detection rules

The default academic/demo rule set includes patterns for commands such as:

- `nmap`
- `nc` / `netcat`
- `curl`
- `wget`
- `tcpdump`
- `hydra`
- `john`
- `hashcat`
- `msfconsole`
- `msfvenom`
- encoded PowerShell and decode patterns

These rules are for demonstration and should be tuned before real-world use.

## Requirements

- Windows 10 or Windows 11
- WSL installed and enabled
- Python 3.10+
- Administrator PowerShell for service installation

Install Python dependencies:

```powershell
pip install -r requirements.txt
```

## Usage

Test the detection rules:

```powershell
python wsl_guardian_service.py --test
```

Run in console/debug mode:

```powershell
python wsl_guardian_service.py --debug
```

Run debug mode without the final global WSL shutdown fallback:

```powershell
python wsl_guardian_service.py --debug --no-shutdown
```

Install as a Windows service from an Administrator PowerShell:

```powershell
python wsl_guardian_service.py --install
python wsl_guardian_service.py --start
```

Stop or remove the service:

```powershell
python wsl_guardian_service.py --stop
python wsl_guardian_service.py --uninstall
```

## Log locations

By default, logs are written under:

```text
C:\ProgramData\WSLGuardian\
```

Main logs:

```text
C:\ProgramData\WSLGuardian\wsl_guardian.log
C:\ProgramData\WSLGuardian\events.jsonl
C:\ProgramData\WSLGuardian\detailed_logs\
```

A sanitized sample log is included in `sample_logs/wsl_guardian_sample.log`.

## Suggested GitHub topics

```text
cybersecurity, wsl, windows-security, python, endpoint-security, threat-detection, siem, blue-team, process-monitoring, edr
```

## Limitations

- Host-side monitoring cannot fully inspect Linux-native process activity inside WSL 2.
- Short-lived commands may finish before the polling loop catches them.
- Some termination attempts may fail without administrator privileges.
- The default rules are intentionally strict for demonstration and may block legitimate admin/developer activity.

## Future improvements

- Add a lightweight Linux-side WSL agent.
- Add a GUI for rule management and log viewing.
- Add Filebeat/Wazuh/Splunk forwarding examples.
- Add YAML/JSON external rule configuration.
- Add unit tests and packaging support.

## Disclaimer

This project is an academic proof-of-concept. Use only in authorized lab or enterprise environments where you have permission to monitor and terminate WSL activity.
