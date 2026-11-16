# Product Requirements & Market Strategy: SOC Log Sentinel

**Product Owner & Lead Engineer:** Muhammed Kaplan (`@mukapo`)  
**Version:** 1.0 (MVP)  
**Target Market:** UK & Ireland SMEs, Managed Service Providers (MSPs), and Tier 1/2 SOC Teams  

---

## 1. Problem Discovery & Root Cause Analysis

### The Core Problem
Small-to-medium enterprises (SMEs) and lean IT teams in the UK and Ireland face a severe cybersecurity blind spot:
1. **Prohibitive SIEM Costs:** Enterprise SIEM platforms (Splunk, Microsoft Sentinel, QRadar) typically cost **£15,000 – £60,000+/year** in licensing and ingestion fees, pricing out SMEs.
2. **Alert Fatigue & Raw Log Noise:** Windows Security Event Logs (`4625`, `4624`, `4720`, `1102`) and Linux `auth.log` files generate thousands of cryptic lines daily. Overworked IT admins ignore them until a breach occurs.
3. **Compliance Pressure:** Frameworks like **UK Cyber Essentials Plus**, **ISO 27001**, and **GDPR** require organizations to demonstrate active log monitoring, incident detection, and audit-ready reporting.
4. **Slow Mean Time to Detect (MTTD):** According to industry benchmarks, SMEs often take weeks to detect credential compromise or unauthorized privilege escalation because they lack automated correlation between failed logins and subsequent successful logins.

---

## 2. Market Analysis & Demand (UK & Ireland)

- **UK Cyber Security Breaches Survey:** Over **50% of UK businesses** report experiencing a cyber breach or attack annually, with phishing and credential brute-force among the top initial access vectors.
- **Ireland Tech & SME Hub:** Under the EU **NIS2 Directive** and Irish NCSC guidelines, mid-market firms and supply-chain vendors must adopt stricter incident detection and reporting workflows.
- **The Market Gap:** There is a massive gap between *raw OS logs (free, unusable at scale)* and *enterprise SIEMs (powerful, expensive, complex)*. Teams need a **zero-dependency, lightweight, MITRE-mapped triage engine** that turns raw logs into actionable security intelligence in seconds.

---

## 3. Target User Personas

### Persona A: "Liam" — Overworked IT / Systems Engineer (SME, Dublin)
- **Context:** Manages 250 endpoints, M365, and Windows Servers alone or in a 2-person team.
- **Pain Point:** Doesn't have time to write KQL queries or maintain a heavy ELK stack. Needs to drop a log export and immediately see if anyone broke in.
- **Job-to-be-Done (JTBD):** *"When I suspect suspicious account activity, I want an instant summary of compromised accounts and privilege changes so I can lock them down in minutes."*

### Persona B: "Sarah" — Tier 1/2 SOC Analyst (MSP, London)
- **Context:** Triages security alerts across 15+ client environments.
- **Pain Point:** Needs standardized **MITRE ATT&CK** mappings and clean JSON/HTML evidence to escalate incidents to clients or Tier 3 engineers.
- **JTBD:** *"When reviewing client security logs, I want correlated multi-stage detections mapped to MITRE ATT&CK so I can reduce false positives and document incidents rapidly."*

### Persona C: "David" — Compliance / IT Director
- **Context:** Prepares for ISO 27001 / Cyber Essentials audits.
- **Pain Point:** Needs non-technical, executive-friendly risk scores and remediation checklists.
- **JTBD:** *"When auditing our security posture, I want a clear HTML executive report showing risk scores and remediation steps."*

---

## 4. MVP Scope & Product Requirements

### In-Scope (v1.0 MVP)
1. **Zero-Dependency CLI Engine:** Built on Python 3 standard library (`json`, `csv`, `argparse`) — runs on any macOS, Linux, or Windows host without `pip` bloat.
2. **Multi-Stage Threat Correlation Rules:**
   - **T1110 (Brute Force):** Detects high-frequency failed logons (`Event ID 4625` / SSH failures).
   - **T1078 (Valid Accounts - Post-Brute-Force Compromise):** Correlates failed logon spikes followed by a successful logon (`4624`) from the same source IP/user.
   - **T1136 / T1098 (Persistence & Privilege Escalation):** Flags new account creation (`4720`) and additions to privileged groups (`4732` Administrators).
   - **T1070.001 (Defense Evasion):** Detects Windows Security Audit Log clearing (`1102`).
   - **T1059.001 (Execution):** Detects obfuscated/encoded PowerShell commands (`-enc`, `Invoke-Expression`, `DownloadString`).
3. **Dual-Audience Output:**
   - Machine-readable `report.json` for SOAR/automation pipelines.
   - Executive & Analyst `report.html` with Risk Score (0–100), Severity Breakdown, Incident Timeline, MITRE ATT&CK tags, and Remediation Playbooks.

### Out-of-Scope (v2.0 Roadmap)
- Real-time syslog / Windows Event Forwarding (WEF) daemon.
- Direct Slack / Microsoft Teams Webhook alerting.
- GeoIP enrichment & Threat Intel feed integration (AbuseIPDB).

---

## 5. Success Metrics (KPIs)

| Metric | Target (MVP) | Measurement Method |
| :--- | :--- | :--- |
| **Time-to-Triage** | < 2 seconds per 10,000 log events | CLI execution benchmark |
| **Correlation Accuracy** | 100% detection on multi-stage test suite | Automated `unittest` suite |
| **Setup Friction** | 0 external dependencies | Pure Python 3 stdlib |
| **Audit Readiness** | 1-click HTML + JSON export | Generated report artifacts |

---

## 6. Market & Business Value

1. **Cost Avoidance:** Replaces £1,000+/month entry-level log analysis tooling for SMEs during incident triage and periodic audits.
2. **MTTD Reduction:** Cuts manual log review from hours to **under 2 seconds**, directly limiting attacker dwell time.
3. **Monetization / MSP Potential:** Can be packaged as a lightweight **"Rapid Compromise Assessment"** tool for UK/Ireland MSPs to run during client onboarding or Cyber Essentials readiness checks.
