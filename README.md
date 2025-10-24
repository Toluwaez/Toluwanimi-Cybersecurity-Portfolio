# 👋🏾 Hi, I’m Toluwanimi

I’m a cybersecurity and IT professional passionate about using technology to protect and empower people.  
Currently exploring SOC automation, threat detection, and vulnerability management.  
On this page, you’ll find projects related to:
- Security monitoring and log analysis
- Python automation for incident response
- Network and vulnerability management
- Cloud security and compliance insights







# Vulnerability Management Case Study
**Folder:** `tenable-vuln-report`  
**Objective:** Demonstrate end-to-end understanding of the vulnerability management lifecycle — from discovery to remediation.

---

## Scenario Overview

This case study simulates a vulnerability assessment using **Tenable.io** on a mid-sized enterprise network.

### Scope:
- 120 endpoints (mix of Windows 10/11 workstations and Windows Server 2019 hosts)
- 10 public-facing web servers
- Cloud footprint: 5 Azure VMs + 2 AWS EC2 instances

### Purpose:
Identify, prioritize, and propose remediation actions for high-risk vulnerabilities across systems.

---

## Included Files

| File | Description |
|------|--------------|
| `tenable_mock_report.pdf` | Sample anonymized Tenable scan report |
| `risk_chart.png` | Visualization of critical/high/medium/low risk distribution |
| `poam_example.xlsx` | Sample Plan of Action & Milestones (POA&M) summary |

---

## Findings Summary

| Severity | Count | Example Vulnerabilities |
|-----------|--------|-------------------------|
| **Critical (CVSS 9.0–10.0)** | 12 | CVE-2023-23397 (Outlook Privilege Escalation), OpenSSL Heartbleed |
| **High (CVSS 7.0–8.9)** | 46 | SMB Signing Disabled, Outdated Apache HTTPD |
| **Medium (CVSS 4.0–6.9)** | 91 | Missing OS Patches, Deprecated TLS Configurations |
| **Low (CVSS < 4.0)** | 54 | Unused open ports, Banner disclosures |

---

## Analysis & Prioritization Strategy

### 1. **Asset Criticality**
- Prioritize systems supporting core business functions (e.g., authentication servers, databases).
- Assign higher weight to **internet-exposed assets**.

### 2. **Exploitability**
- Cross-check critical findings in **ExploitDB**, **CISA KEV**, and **Metasploit Framework**.
- Confirm which vulnerabilities are **actively exploited in the wild**.

### 3. **Compensating Controls**
- Determine if compensating security controls (e.g., WAF, segmentation, endpoint EDR) reduce immediate risk.

### 4. **Remediation Priority**
1. **Patch critical CVEs** with known exploits first (e.g., CVE-2023-23397).  
2. **Reconfigure services** to enforce secure defaults (e.g., enable SMB signing).  
3. **Remove legacy protocols** and enforce TLS 1.2+.  
4. **Schedule medium/low-risk items** during next maintenance cycle.

---

## Recommended Remediation Actions

| Category | Action | Target SLA |
|-----------|---------|------------|
| Critical | Apply vendor patches or mitigations within **72 hours** | 3 days |
| High | Remediate within **7 business days** | 1 week |
| Medium | Address in **next patch cycle (30 days)** | 30 days |
| Low | Review quarterly or as part of hardening baseline | 90 days |

---

## POA&M Example

[Download POA&M Excel File](poam_example.xlsx)

**Fields:** Vulnerability ID • Severity • System Affected • Recommended Fix • Owner • Target Date • Status

---

## 📈 Risk Visualization

![Risk Chart](risk_chart.png)

---

## Tools Used
- **Tenable.io** – vulnerability scanning & risk scoring  
- **Splunk / ELK** – log correlation & asset tracking  
- **Excel / Power BI** – data visualization  
- **NIST 800-53** & **NIST SP 800-40 Rev.4** – patch management framework reference

---

## Lessons Learned
- Automating scan ingestion into dashboards accelerates triage.  
- Cross-mapping vulnerabilities with asset criticality prevents “patch everything” burnout.  
- Clear POA&M tracking drives accountability and visibility for remediation.  
- Integrating Tenable with SIEMs (e.g., Splunk) enhances real-time vulnerability awareness.

---

> 💡 *This case study is based on simulated data and reflects standard vulnerability management practices used in enterprise environments.*

---
---

## _INVESTIGATIONS_
---
### Q-RADAR

# Cybersecurity Investigation: Cisco IOS HTTP Server Exec Command Execution Attempt

**Analyst:** Toluwanimi Oladele-Ajose  
**Date:** March 2025  
**Platform:** QRadar | Splunk | Suricata | VirusTotal | Talos | Shodan  

---

## Overview
This investigation focused on a **possible Cisco IOS HTTP Server Exec Command Execution Attempt** detected by QRadar.  
The goal was to validate the alert, assess threat legitimacy, and determine potential exposure or next steps for mitigation.

---

## 📋 Offense Details
**QRadar Offense ID:** `54570`  
**Description:** Possible Cisco IOS HTTP Server Exec Command Execution Attempt  
**Victim:** `38.242.128.144`  

**Encoded log:**  
/level/15/exec/-/sh/run/CR

**Decoded log:**  
No decoding needed. After normalizing: `/level/15/exec/-/sh/run/CR`

---

## 💻 Attacker Information
| Attribute | Value |
|------------|--------|
| **IP Address** | `45.155.91.226` |
| **User Agent** | `libwww-perl/6.67` |
| **Notes** | Perl-based HTTP client used for automated scanning or exploitation |

---

## 🔎 Threat Intelligence
**VirusTotal:** [View Analysis](https://www.virustotal.com/gui/ip-address/45.155.91.226)  
> 7/94 security vendors flagged this IP as malicious  

**Talos Reputation:**  
- Sender IP Reputation: **Poor**  
- Web Reputation: **Questionable**

**Blocklists:**  
- CBL.ABUSEAT.ORG → **Listed**  
- Others → Not listed  

**Shodan Result:** [View Host](https://www.shodan.io/host/45.155.91.226)  
- **Open Ports:** 22 (SSH)

**AbuseIPDB:** [View Report](https://www.abuseipdb.com/check/45.155.91.226)  
- Reported **1,741 times**  
- **Confidence of Abuse:** 100%

---

## Log Analysis
**Splunk Findings:**
- 208 events associated with `45.155.91.226`
- Filtering for Cisco reduced to **19 events**

- 
**Raw Suricata Data Sample:**
```json
{
  "timestamp": "2025-03-15T06:14:36.828784-0400",
  "src_ip": "45.155.91.226",
  "dest_ip": "38.242.128.144",
  "proto": "TCP",
  "event_type": "alert",
  "alert": {
    "signature": "ET WEB_SERVER Cisco IOS HTTP Server Exec Command Execution Attempt",
    "severity": 1
  },
  "http": {
    "url": "/level/15/exec/-/sh/run/CR",
    "http_user_agent": "libwww-perl/6.67",
    "status": 403
  }
}
```

---

## Additional Findings
This IP was reported **1,741 times** on [AbuseIPDB](https://www.abuseipdb.com/check/45.155.91.226)  
→ **Confidence of abuse: 100%**

---

## Analyst Assessment
The observed request targeted a web path:  
`/level/15/exec/-/sh/run/CR`  

This path resembles a **remote code execution (RCE)** attempt — specifically targeting devices or services that expose shell execution endpoints (e.g., CI/CD pipelines, network admin panels, or custom APIs).

**Behavioral Indicators:**
- Not typical of normal user traffic  
- Automated scanning/probing behavior is strongly suspected  
- **Potential intent:** gain unauthorized remote access or run shell commands

---

## Recommended Actions
- Audit and restrict access to `/exec/` or similar endpoints  
- Enforce strict authentication and **Role-Based Access Control (RBAC)**  
- Monitor logs for repeated shell execution patterns  
- Disable shell access via HTTP unless explicitly required and secured

---

## Lessons Learned
- Automating threat validation using **QRadar + VirusTotal + Shodan** improves triage efficiency  
- Common user agents like **libwww-perl** are often seen in exploit scanning  
- Structured documentation accelerates collaboration during incident response  

---

## Tools Used
**QRadar • Splunk • Suricata • VirusTotal • Shodan • Talos Intelligence • AbuseIPDB**

---

📄 **Created by:** *Toluwanimi Oladele-Ajose*  
**SOC & Vulnerability Management Enthusiast**

---
---
### CROWDSTRIKE
---

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

---
---


# Cyberint Threat Intelligence Challenge  
### Conducted by: Toluwanimi Oladele-Ajose  
**Position Simulated:** Threat Intelligence Analyst – English Speaker  
**Organization:** Check Point Software Technologies (Cyberint Division)  
**Year:** 2024  

---

## Scenario Overview  
The following challenge simulates daily analytical tasks of a Threat Intelligence Analyst.  
Each section represents a real-world reporting task: assessing compromised data, analyzing malicious code exposure, investigating malware, and profiling a threat actor.  

---

## PayPal Security Alert – Compromised Assets  

### Description  
This alert concerns the exposure of a **potentially full PayPal customer record** linked to `kathleenrfiles@gmail.com`.  
The data includes sensitive details such as alleged passwords, partial credit card numbers, a confirmed bank account (Regions Bank ending in 8833), **session tokens**, and cookies — all of which could be used to hijack authenticated sessions.  

Session tokens maintain login states. If stolen, they allow an attacker to gain **unauthorized access without credentials**, posing a **critical account takeover risk**.  

The presence of financial data and routing numbers suggests the artifact originated from a compromised endpoint or credential harvesting via phishing or malware.

### Potential Impact  
- Full account compromise and fraudulent fund transfers  
- Social engineering targeting the victim  
- Bank or card exploitation  
- PayPal brand and reputational damage  

### Recommendations  
- **Immediate containment:** Temporarily lock account, notify customer, enforce re-authentication  
- **Education:** Remind users about credential reuse and phishing  
- **Forensic actions:** Review logs, session reuse, IP addresses (`45.114.144.146`), and cookie reuse patterns  
- **Policy improvement:** Strengthen session management — shorter expirations, token-IP binding  
- **Long-term:** Enhance behavioral analytics and fraud detection triggers  

---

## Barclays Bank Security Alert – Public GitHub Exposure  

### Description  
A **public automation script** targeting **Barclays Bank** online login was found on GitHub.  
The script, built with **Puppeteer**, automates credential input, MFA handling, and data scraping — effectively simulating an entire user login flow.  

Such automation can be exploited for large-scale credential stuffing or brute force attacks when attackers possess stolen credentials.

### Potential Impact  
- Increased risk of automated **account takeovers**  
- **Financial loss** and exposure of sensitive customer information  
- **Reputation damage** due to public exploitation of login systems  

### Recommendations  
- Detect and block **headless browser activity (Puppeteer)**  
- Use **CAPTCHAs, device fingerprinting, and behavioral analytics**  
- Report/remove malicious repositories  
- Improve MFA hardening and adaptive authentication  

**Technical Indicators:**  
- Script hosted on GitHub (`barclayscrape/session.js`)  
- Puppeteer-based headless browser strings  

---

## Malware Analysis – RedLine Info-Stealer  

### Distribution  
- Phishing emails and malicious attachments  
- Fake software installers, cracked apps, and **SEO-poisoned sites**  
- Hijacked Facebook business pages promoting fake AI tools  

### Main Functionalities  
- Steals passwords, cookies, wallets, and browser data  
- Collects system info, antivirus presence, and IP/geo  
- Downloads additional payloads (e.g., ransomware)  

### Indicators of Compromise (IOCs)  
- **URLs:** `pdfconvertercompare[.]com`, fake Facebook pages  
- **Network:** Outbound connections to suspicious IPs via uncommon ports  
- **Persistence:** `%AppData%\Redline`, registry entries for autostart  

---

## Threat Actor Investigation – `salman0x01@yandex[.]com`  

### Summary  
This email is embedded in multiple phishing kits and malware samples targeting **Philippine financial institutions**.  

**Probable Identity:** *Salman Arif Khan* — GitHub profile claims to be a “cybersecurity researcher,” but the address appears in artifacts linked to **phishing campaigns impersonating BDO Bank**.  

### Findings  
- **Email:** `salman0x01@yandex.com` (confirmed IOC)  
- **GitHub:** [github.com/salman0x01](https://github.com/salman0x01)  
- **Phishing Domain:** `bdoonline-verify[.]biz` linked via community posts and VirusTotal  

No alternate contact info (Discord, ICQ, phone) was discovered.  
Actor may maintain **tight operational security** or a **limited public footprint**.  

### Tools & Methods Used  
- **OSINT Sources:** VirusTotal, Hybrid Analysis, Twitter/X, PassiveDNS  
- **Verification:** Cross-referenced sandbox data and social media artifacts  
- **Pivoting:** GitHub repo email associations, WHOIS enrichment  

### Assessment  
The email serves as a **credible operational indicator** tied to phishing-kit infrastructure.  
Further infrastructure mapping and dark web monitoring are recommended to identify hosting assets for takedown.  

---

### Lessons Learned  
- **Public exposure** of scripts and stolen data increases organizational risk.  
- **RedLine malware** exemplifies multi-channel distribution — social, fake downloads, and ads.  
- **Threat actor tracking** through OSINT and sandbox pivots remains vital to attribution.  

---

**Created by:** *Toluwanimi Oladele-Ajose*  
*Threat Intelligence & Vulnerability Management Enthusiast*  
[GitHub Portfolio](https://github.com/toluwaez)  

