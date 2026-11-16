# SOC Log Sentinel 🛡️

**Interactive Mini-SIEM, Multi-Format Threat Detection & MITRE ATT&CK Triage Engine**  
Built with a **Product-First + Security Engineering** mindset for UK & Ireland SMEs, MSPs, and SOC Teams.

> 📄 **Product & Market Strategy:** See [PRD & Market Analysis](docs/PRD_AND_MARKET_ANALYSIS.md) for the full Problem Discovery, UK/IE Market Gap, User Personas, KPIs, and Business Value case study.

---

## 🎯 Why This Exists (The Market Problem)
SMEs and lean IT teams cannot afford £15k–£60k/year enterprise SIEM licenses, yet they face strict **UK Cyber Essentials**, **ISO 27001**, and **EU NIS2** monitoring requirements. Raw Windows/Linux security logs are too noisy for manual review.

**SOC Log Sentinel** bridges that gap: analyze **Windows Event Logs (JSON/CSV)** and **Linux `/var/log/auth.log`** via a **local Interactive Web SIEM Console** or **CLI**, generating executive HTML reports and SOAR-ready JSON with **zero external Python dependencies**.

---

## 🔍 Detection Capabilities (8 MITRE ATT&CK Rules)

| Rule ID | Detection | MITRE ATT&CK | Severity |
| :--- | :--- | :--- | :--- |
| `SOC-001` | Brute Force / Password Guessing (`4625` / SSH) | `T1110.001` Brute Force | `MEDIUM` |
| `SOC-002` | **Post-Brute-Force Compromise** (`4625` spike → `4624`) | `T1078` Valid Accounts | `CRITICAL` |
| `SOC-003` | Unauthorized Account Creation (`4720`) | `T1136` Create Account | `HIGH` |
| `SOC-004` | Privileged Group Escalation (`4732` Administrators) | `T1098` Account Manipulation | `CRITICAL` |
| `SOC-005` | Security Audit Log Cleared (`1102`) | `T1070.001` Defense Evasion | `CRITICAL` |
| `SOC-006` | Obfuscated / Encoded PowerShell (`-enc`, `IEX`) | `T1059.001` PowerShell | `HIGH` |
| `SOC-007` | Suspicious Linux Sudo Escalation (`usermod -aG sudo`) | `T1548.003` Sudo Abuse | `CRITICAL` |
| `SOC-008` | Password Spraying Across Multiple Accounts | `T1110.003` Password Spraying | `HIGH` |

---

## 🚀 Quick Start

### Option 1: Interactive Web SIEM Console
```bash
python3 src/web_app.py
# Open http://127.0.0.1:8080 in your browser
# Paste raw logs, upload files, or click 1-click Attack Scenarios!
```

### Option 2: CLI & Automated Report Export
```bash
# Analyze Windows AD Multi-Stage Attack (JSON)
python3 src/detector.py --input data/sample_security_events.json --out-dir output

# Analyze Linux SSH + Sudo Attack (auth.log)
python3 src/detector.py --input data/sample_linux_auth.log --out-dir output

# Run Automated Unit Test Suite
python3 -m unittest discover -s tests -v
```

---

## 👤 Author
**Muhammed Kaplan** (`@mukapo`)  
- GitHub: [github.com/mukapo](https://github.com/mukapo)  
- LinkedIn: [linkedin.com/in/muha-kaplan](https://www.linkedin.com/in/muha-kaplan/)
