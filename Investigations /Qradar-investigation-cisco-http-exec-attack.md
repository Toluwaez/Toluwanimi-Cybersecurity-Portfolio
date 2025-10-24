# Cybersecurity Investigation: Cisco IOS HTTP Server Exec Command Execution Attempt

**Analyst:** Toluwanimi Oladele-Ajose  
**Date:** March 2025  
**Platform:** QRadar | Splunk | Suricata | VirusTotal | Talos | Shodan  

---

## 🧠 Overview
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

## 🧩 Log Analysis
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

## 📊 Additional Findings
This IP was reported **1,741 times** on [AbuseIPDB](https://www.abuseipdb.com/check/45.155.91.226)  
→ **Confidence of abuse: 100%**

---

## 🧠 Analyst Assessment
The observed request targeted a web path:  
`/level/15/exec/-/sh/run/CR`  

This path resembles a **remote code execution (RCE)** attempt — specifically targeting devices or services that expose shell execution endpoints (e.g., CI/CD pipelines, network admin panels, or custom APIs).

**Behavioral Indicators:**
- Not typical of normal user traffic  
- Automated scanning/probing behavior is strongly suspected  
- **Potential intent:** gain unauthorized remote access or run shell commands

---

## 🛠️ Recommended Actions
- Audit and restrict access to `/exec/` or similar endpoints  
- Enforce strict authentication and **Role-Based Access Control (RBAC)**  
- Monitor logs for repeated shell execution patterns  
- Disable shell access via HTTP unless explicitly required and secured

---

## 📘 Lessons Learned
- Automating threat validation using **QRadar + VirusTotal + Shodan** improves triage efficiency  
- Common user agents like **libwww-perl** are often seen in exploit scanning  
- Structured documentation accelerates collaboration during incident response  

---

## 🧩 Tools Used
**QRadar • Splunk • Suricata • VirusTotal • Shodan • Talos Intelligence • AbuseIPDB**

---

📄 **Created by:** *Toluwanimi Oladele-Ajose*  
**SOC & Vulnerability Management Enthusiast**

---



