# SOC Log Sentinel 🛡️

[![CI](https://github.com/mukapo/soc-log-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/mukapo/soc-log-sentinel/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-emerald)
![License: MIT](https://img.shields.io/badge/License-MIT-indigo)

**Interactive Mini-SIEM, Multi-Layer Threat Detection & MITRE ATT&CK Triage Engine**  
Built with a **Product-First + Security Engineering** mindset for UK & Ireland SMEs, MSPs, and SOC Teams.

> 📄 **Product Strategy:** [PRD & Market Analysis](docs/PRD_AND_MARKET_ANALYSIS.md) (Problem Discovery, UK/IE Market Gap, Personas, KPIs)  
> 🏗️ **System Design:** [Architecture & Pipeline Diagram](docs/ARCHITECTURE.md)

---

## 🎯 Why This Exists
SMEs and lean IT teams cannot afford £15k–£60k/year enterprise SIEM licenses, yet they face strict **UK Cyber Essentials**, **ISO 27001**, and **EU NIS2** monitoring requirements.

**SOC Log Sentinel** bridges that gap across **3 infrastructure layers** — **Windows AD/PowerShell**, **Linux SSH/PAM/Sudo**, and **Nginx/Apache Web Servers** — via an **Interactive Web SIEM Console** or **CLI** with **zero external dependencies**.

---

## 🔍 Detection Capabilities (10 MITRE ATT&CK Rules)

| Rule ID | Layer | Detection | MITRE ATT&CK | Severity |
| :--- | :--- | :--- | :--- | :--- |
| `SOC-001` | Windows / Linux | Brute Force / Password Guessing (`4625` / SSH) | `T1110.001` Brute Force | `MEDIUM` |
| `SOC-002` | Windows / Linux | **Post-Brute-Force Compromise** (`4625` → `4624`) | `T1078` Valid Accounts | `CRITICAL` |
| `SOC-003` | Windows AD | Unauthorized Account Creation (`4720`) | `T1136` Create Account | `HIGH` |
| `SOC-004` | Windows AD | Privileged Group Escalation (`4732` Administrators) | `T1098` Account Manipulation | `CRITICAL` |
| `SOC-005` | Windows AD | Security Audit Log Cleared (`1102`) | `T1070.001` Defense Evasion | `CRITICAL` |
| `SOC-006` | Windows Endpoint | Obfuscated / Encoded PowerShell (`-enc`, `IEX`) | `T1059.001` PowerShell | `HIGH` |
| `SOC-007` | Linux OS | Suspicious Sudo Escalation (`usermod -aG sudo`) | `T1548.003` Sudo Abuse | `CRITICAL` |
| `SOC-008` | Windows / Linux | Password Spraying Across Multiple Accounts | `T1110.003` Password Spraying | `HIGH` |
| `SOC-009` | Web / WAF | Web Exploit (SQLi, XSS, Path Traversal, Log4j) | `T1190` Exploit Public App | `CRITICAL` |
| `SOC-010` | Web / WAF | Automated Web Scanner (`sqlmap`, `Gobuster`, `Nuclei`) | `T1595.003` Wordlist Scanning | `HIGH` |

---

## 🚀 Quick Start

### Option 1: Interactive Web SIEM Console
```bash
python3 src/web_app.py
# Open http://127.0.0.1:8080 in your browser
```

### Option 2: CLI & Automated Report Export
```bash
# Windows AD Multi-Stage Intrusion (JSON)
python3 src/detector.py --input data/sample_security_events.json --out-dir output

# Linux SSH + Sudo Attack (auth.log)
python3 src/detector.py --input data/sample_linux_auth.log --out-dir output

# Web Server Attacks (Nginx / Apache Access Log)
python3 src/detector.py --input data/sample_web_access.log --out-dir output

# Live macOS Unified Log Scan (macOS only)
python3 src/detector.py --live-macos --hours 24 --out-dir output

# Run Automated Unit Test Suite
python3 -m unittest discover -s tests -v
```

---

## 📊 Real-World Benchmark (`Loghub OpenSSH_2k.log`)
Validated against **2,000 lines of real production OpenSSH server logs** (`LabSZ` server via [logpai/loghub](https://github.com/logpai/loghub)):
- **Events Parsed:** `1,125` authentication events
- **Correlated Alerts Triggered:** `48` (`Posture: CRITICAL 100/100`)
  - `12x` **Password Spraying (`SOC-008` / `T1110.003`)** — e.g., botnet IPs `187.141.143.180` (29 targeted accounts) and `103.99.0.122` (20 targeted accounts)
  - `36x` **Brute Force (`SOC-001` / `T1110.001`)** — high-frequency guessing against `root`, `admin`, `deploy`, `webmaster`
  - `0x` **Successful Compromises (`SOC-002`)** — confirming perimeter resilience

---

## 👤 Author
**Muhammed Kaplan** (`@mukapo`)  
- Portfolio: [mukapo.github.io](https://mukapo.github.io)  
- GitHub: [github.com/mukapo](https://github.com/mukapo)  
- LinkedIn: [linkedin.com/in/muha-kaplan](https://www.linkedin.com/in/muha-kaplan/)
