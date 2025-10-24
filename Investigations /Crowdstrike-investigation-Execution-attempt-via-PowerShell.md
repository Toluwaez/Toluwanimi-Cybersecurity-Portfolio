# Investigation Report: Execution Attempt Via PowerShell  
**Incident:** PowerShell execution attempt bypassing AMSI/ExecutionPolicy  
**Date:** March 2025

---

## Summary
A detection showed a PowerShell command that temporarily bypassed the system execution policy to run a script from a user’s `Downloads` folder. The behavior is consistent with adversaries attempting to execute unsigned or untrusted PowerShell code in memory or on disk.

---

## CrowdStrike Detection
**CrowdStrike Link:** [CrowdStrike Detection](https://falcon.us-2.crowdstrike.com/activity-v2/detections/55ff35c57f0441f19baad0a47c239f7d:ind:fd0ae32b624a4baa83845321c1cf0e52:5463454559613-10163-772624)  
> *Note: Link is internal to CrowdStrike and may require appropriate credentials to view.*

---

## Affected Hosts & Users
- **Host:** `VMI1146645`  
- **User:** `JOHN`  
- **Number of detections:** 1

---

## Description
- **Behavior observed:** A PowerShell command was executed that checks the current execution policy and, if not set to `AllSigned`, temporarily sets process scope policy to `Bypass` and executes a script named `Thunderbirdresetscript.ps1` from the user’s Downloads folder.  
- **Tactics / Techniques:**  
  - Tactic: Execution  
  - Technique: PowerShell

---

## Observed Command (Command Line)
```text
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\john.VMI1146645\Downloads\Thunderbirdresetscript.ps1'"
```

---

**Analysis:**  
This command temporarily relaxes script execution enforcement in the process scope so the PowerShell interpreter can run a script that may be unsigned. This is a common technique used to run malicious or unvetted scripts without changing the machine-wide policy.  

---

### Observed Script Details  

**File Name:** `Thunderbirdresetscript.ps1`  
**Observed Path / Process:** `\Device\HarddiskVolume2\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`  
**SHA256:** `85fe2c4d21017f8993e836715cd0cb733df7815a668e5006925e7b0483a0a814`  

> Include sample script content here **only if safe and non-sensitive**.  
> If the script contains active malware or customer data, **do not publish** it publicly.  

---

### Analyst Assessment  

The command uses a **process-scoped bypass** of PowerShell’s execution policy to run a local script.  
This allows execution of unsigned code while avoiding persistent system changes — a red flag for adversarial activity.  

Given the script’s origin (`Downloads` folder), this could indicate either:  
- a benign user action (legitimate script utility), or  
- a malicious payload execution.  

**Immediate concerns:**  
- Script may execute secondary payloads, modify system settings, or run in-memory code.  
- Possible network communications for staging or exfiltration.  

---

### Recommended Actions  

- **Isolate Host:** Quarantine `VMI1146645` pending full analysis.  
- **File Analysis:** Submit hash to VirusTotal / sandbox environment for static + dynamic analysis.  
- **Endpoint Hunt:** Search for similar command-line patterns across endpoints (`Set-ExecutionPolicy -Scope Process Bypass`).  
- **User Verification:** Confirm script origin and legitimacy.  
- **Block/Contain:** If confirmed malicious, block file hash, command-line signatures, and related indicators in EDR/NDR systems.  
- **Harden Policies:** Enforce `ConstrainedLanguageMode`, enable AMSI hardening, and implement AppLocker/WDAC policies.  
- **Monitor:** Add detection rules for temporary execution-policy bypass and PowerShell executions from user directories.  

---

### Lessons Learned  

- Process-scoped policy bypasses are common adversarial techniques — focus detections on **command-line behavior**, not just file signatures.  
- EDR telemetry (parent/child process, network calls, script origin) is key to context.  
- Train users to avoid running downloaded scripts unless verified.  
- Restrict PowerShell execution rights for non-admin users.  

---

### Tools Used  
CrowdStrike Falcon • EDR Telemetry • Hash Analysis (SHA256) • VirusTotal / Sandbox • Internal Log Search  
