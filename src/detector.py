"""
SOC Log Sentinel - Lightweight Threat Detection & MITRE ATT&CK Triage Engine.
Supports Windows Security Event Logs (JSON/CSV) and Linux Syslog/auth.log.
Zero-dependency Python 3 implementation designed for UK/Ireland SMEs & SOC Teams.

Author: Muhammed Kaplan (@mukapo)
"""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
}

SUSPICIOUS_PS_PATTERNS = [
    r"-enc\b",
    r"-encodedcommand\b",
    r"invoke-expression",
    r"\biex\b",
    r"downloadstring",
    r"net\.webclient",
    r"-w\s+hidden",
]

SUSPICIOUS_SUDO_PATTERNS = [
    r"usermod\s+.*-aG\s+(sudo|wheel|admin)",
    r"chmod\s+\+s",
    r"/etc/shadow",
    r"visudo",
    r"nc\s+-e",
    r"bash\s+-i",
]

SSH_FAIL_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)
SSH_SUCCESS_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted (?:password|publickey) for (?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)
SUDO_CMD_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo(?:\[\d+\])?:\s+"
    r"(?P<user>\S+)\s+:.*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)


@dataclass
class Alert:
    """Represents a correlated security detection mapped to MITRE ATT&CK."""

    rule_id: str
    title: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    host: str
    source_ip: str
    user: str
    timestamp: str
    evidence: str
    remediation: str


@dataclass
class AnalysisReport:
    """Aggregated security triage report for JSON, CLI, Web UI, and HTML export."""

    generated_at: str
    input_file: str
    total_events: int
    total_alerts: int
    risk_score: int
    risk_level: str
    severity_counts: dict[str, int] = field(default_factory=dict)
    affected_hosts: list[str] = field(default_factory=list)
    top_source_ips: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)


def parse_auth_log_lines(lines: list[str]) -> list[dict[str, Any]]:
    """Parse Linux /var/log/auth.log lines into normalized security event dicts."""
    events: list[dict[str, Any]] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        if m := SSH_FAIL_RE.match(line):
            events.append(
                {
                    "timestamp": m.group("ts"),
                    "host": m.group("host"),
                    "event_id": 4625,
                    "user": m.group("user"),
                    "source_ip": m.group("ip"),
                    "status": "Failure",
                    "platform": "linux_ssh",
                    "details": line,
                }
            )
        elif m := SSH_SUCCESS_RE.match(line):
            events.append(
                {
                    "timestamp": m.group("ts"),
                    "host": m.group("host"),
                    "event_id": 4624,
                    "user": m.group("user"),
                    "source_ip": m.group("ip"),
                    "status": "Success",
                    "platform": "linux_ssh",
                    "details": line,
                }
            )
        elif m := SUDO_CMD_RE.match(line):
            events.append(
                {
                    "timestamp": m.group("ts"),
                    "host": m.group("host"),
                    "event_id": 4672,
                    "user": m.group("user"),
                    "target_user": m.group("target_user"),
                    "source_ip": "127.0.0.1",
                    "command_line": m.group("cmd").strip(),
                    "status": "Success",
                    "platform": "linux_sudo",
                    "details": line,
                }
            )
    return events


def parse_raw_text(raw_text: str, format_hint: str = "auto") -> list[dict[str, Any]]:
    """Parse raw JSON, CSV, or Linux auth.log text in memory."""
    stripped = raw_text.strip()
    if not stripped:
        return []

    if format_hint == "json" or (format_hint == "auto" and stripped.startswith("[")):
        data = json.loads(stripped)
        if not isinstance(data, list):
            raise ValueError("JSON log payload must be a list of event objects.")
        return data

    if format_hint == "csv" or (
        format_hint == "auto" and "," in stripped.splitlines()[0] and "event_id" in stripped.splitlines()[0].lower()
    ):
        reader = csv.DictReader(io.StringIO(stripped))
        events: list[dict[str, Any]] = []
        for row in reader:
            if "event_id" in row and str(row["event_id"]).isdigit():
                row["event_id"] = int(row["event_id"])
            events.append(row)
        return events

    return parse_auth_log_lines(stripped.splitlines())


def load_events(file_path: Path) -> list[dict[str, Any]]:
    """Load security events from a JSON, CSV, or Linux .log/.txt file."""
    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    suffix = file_path.suffix.lower()
    content = file_path.read_text(encoding="utf-8")
    if suffix == ".json":
        return parse_raw_text(content, format_hint="json")
    if suffix == ".csv":
        return parse_raw_text(content, format_hint="csv")
    if suffix in {".log", ".txt"}:
        return parse_raw_text(content, format_hint="log")

    raise ValueError(f"Unsupported file format '{suffix}'. Use .json, .csv, .log, or .txt.")


def detect_threats(
    events: list[dict[str, Any]],
    brute_force_threshold: int = 4,
    spray_user_threshold: int = 3,
) -> list[Alert]:
    """Run multi-stage correlation and signature rules across security events."""
    alerts: list[Alert] = []
    failed_by_target: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    failed_users_by_ip: dict[tuple[str, str], set[str]] = defaultdict(set)
    ip_last_ts: dict[tuple[str, str], str] = {}

    for ev in events:
        event_id = int(ev.get("event_id", 0) or 0)
        host = str(ev.get("host", "UNKNOWN"))
        ip = str(ev.get("source_ip", "UNKNOWN"))
        user = str(ev.get("user", "UNKNOWN"))
        ts = str(ev.get("timestamp", ""))
        cmd = str(ev.get("command_line", ""))

        # Track failed logons (4625 / SSH Failed)
        if event_id == 4625:
            failed_by_target[(host, ip, user)].append(ev)
            failed_users_by_ip[(host, ip)].add(user)
            ip_last_ts[(host, ip)] = ts

        # Rule 2: Post-Brute-Force Account Compromise (T1078)
        elif event_id == 4624:
            prior_failures = failed_by_target.get((host, ip, user), [])
            if len(prior_failures) >= brute_force_threshold:
                alerts.append(
                    Alert(
                        rule_id="SOC-002",
                        title="Potential Account Compromise (Success After Brute Force)",
                        severity="CRITICAL",
                        mitre_tactic="Initial Access / Persistence",
                        mitre_technique="T1078 - Valid Accounts",
                        host=host,
                        source_ip=ip,
                        user=user,
                        timestamp=ts,
                        evidence=f"Successful logon (4624) from {ip} after {len(prior_failures)} failed attempts.",
                        remediation="Immediately revoke active sessions, reset user password, enforce MFA, and block source IP.",
                    )
                )

        # Rule 3: Unauthorized Account Creation (T1136)
        elif event_id == 4720:
            actor = str(ev.get("actor", "UNKNOWN"))
            alerts.append(
                Alert(
                    rule_id="SOC-003",
                    title="New Local/Domain Account Created",
                    severity="HIGH",
                    mitre_tactic="Persistence",
                    mitre_technique="T1136 - Create Account",
                    host=host,
                    source_ip=ip,
                    user=user,
                    timestamp=ts,
                    evidence=f"Account '{user}' created by actor '{actor}'.",
                    remediation="Verify change ticket in ITSM (ServiceNow/Jira). Disable account if unauthorized.",
                )
            )

        # Rule 4: Privileged Group Escalation (T1098)
        elif event_id == 4732:
            group = str(ev.get("group", "Privileged Group"))
            actor = str(ev.get("actor", "UNKNOWN"))
            alerts.append(
                Alert(
                    rule_id="SOC-004",
                    title="Privilege Escalation: User Added to Privileged Group",
                    severity="CRITICAL",
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1098 - Account Manipulation",
                    host=host,
                    source_ip=ip,
                    user=user,
                    timestamp=ts,
                    evidence=f"User '{user}' added to '{group}' by '{actor}'.",
                    remediation="Remove unauthorized admin membership immediately and audit all actions by actor.",
                )
            )

        # Rule 5: Audit Log Cleared / Defense Evasion (T1070.001)
        elif event_id == 1102:
            alerts.append(
                Alert(
                    rule_id="SOC-005",
                    title="Security Audit Log Cleared (Defense Evasion)",
                    severity="CRITICAL",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1070.001 - Clear Windows Event Logs",
                    host=host,
                    source_ip=ip,
                    user=user,
                    timestamp=ts,
                    evidence=f"Security audit log wiped on {host} by '{user}'.",
                    remediation="Isolate host immediately, preserve memory/disk forensics, and check SIEM backups.",
                )
            )

        # Rule 7: Linux Suspicious Sudo Escalation (T1548.003)
        elif event_id == 4672 and cmd:
            if any(re.search(pat, cmd, re.IGNORECASE) for pat in SUSPICIOUS_SUDO_PATTERNS):
                alerts.append(
                    Alert(
                        rule_id="SOC-007",
                        title="Suspicious Linux Sudo Privilege Escalation",
                        severity="CRITICAL",
                        mitre_tactic="Privilege Escalation",
                        mitre_technique="T1548.003 - Sudo and Sudo Caching",
                        host=host,
                        source_ip=ip,
                        user=user,
                        timestamp=ts,
                        evidence=f"High-risk sudo command executed by '{user}': {cmd}",
                        remediation="Audit /etc/sudoers and /etc/passwd, revoke user sudo privileges, and inspect host.",
                    )
                )

        # Rule 6: Suspicious Encoded PowerShell Execution (T1059.001)
        if cmd and event_id != 4672 and any(re.search(pat, cmd, re.IGNORECASE) for pat in SUSPICIOUS_PS_PATTERNS):
            alerts.append(
                Alert(
                    rule_id="SOC-006",
                    title="Suspicious Obfuscated PowerShell Execution",
                    severity="HIGH",
                    mitre_tactic="Execution",
                    mitre_technique="T1059.001 - PowerShell",
                    host=host,
                    source_ip=ip,
                    user=user,
                    timestamp=ts,
                    evidence=f"Command matched obfuscation/download signature: {cmd[:110]}...",
                    remediation="Decode Base64 payload, quarantine endpoint via EDR, and block C2 IP/domain.",
                )
            )

    # Rule 1: Aggregate Single-User Brute Force (T1110.001)
    for (host, ip, user), failures in failed_by_target.items():
        if len(failures) >= brute_force_threshold:
            alerts.append(
                Alert(
                    rule_id="SOC-001",
                    title="Brute Force / Credential Stuffing Detected",
                    severity="MEDIUM",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110.001 - Password Guessing",
                    host=host,
                    source_ip=ip,
                    user=user,
                    timestamp=str(failures[-1].get("timestamp", "")),
                    evidence=f"{len(failures)} failed logon attempts targeting '{user}' from {ip}.",
                    remediation="Block offending IP at firewall/Conditional Access and verify account lockout policies.",
                )
            )

    # Rule 8: Password Spraying across Multiple Accounts (T1110.003)
    for (host, ip), users in failed_users_by_ip.items():
        if len(users) >= spray_user_threshold:
            alerts.append(
                Alert(
                    rule_id="SOC-008",
                    title="Password Spraying Attack Across Multiple Accounts",
                    severity="HIGH",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110.003 - Password Spraying",
                    host=host,
                    source_ip=ip,
                    user=", ".join(sorted(users)),
                    timestamp=ip_last_ts.get((host, ip), ""),
                    evidence=f"Source IP {ip} probed {len(users)} distinct accounts ({', '.join(sorted(users))}) on {host}.",
                    remediation="Block source IP at perimeter/fail2ban and enable smart lockout + MFA.",
                )
            )

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: (severity_order.get(a.severity, 9), a.timestamp))
    return alerts


def build_report(events: list[dict[str, Any]], alerts: list[Alert], input_file: str) -> AnalysisReport:
    """Calculate risk posture and assemble the structured report."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    raw_score = 0
    hosts = sorted({a.host for a in alerts})
    ip_counter = Counter(a.source_ip for a in alerts if a.source_ip not in {"UNKNOWN", "127.0.0.1"})

    for alert in alerts:
        counts[alert.severity] = counts.get(alert.severity, 0) + 1
        raw_score += SEVERITY_WEIGHTS.get(alert.severity, 5)

    risk_score = min(100, raw_score)
    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 45:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MODERATE"
    else:
        risk_level = "LOW"

    top_ips = [{"ip": ip, "alerts": cnt} for ip, cnt in ip_counter.most_common(5)]

    return AnalysisReport(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        input_file=input_file,
        total_events=len(events),
        total_alerts=len(alerts),
        risk_score=risk_score,
        risk_level=risk_level,
        severity_counts=counts,
        affected_hosts=hosts,
        top_source_ips=top_ips,
        alerts=alerts,
    )


def export_json(report: AnalysisReport, out_path: Path) -> None:
    """Write machine-readable JSON report."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2)


def export_html(report: AnalysisReport, out_path: Path) -> None:
    """Generate an executive and SOC analyst HTML triage report."""
    out_path.parent.mkdir(parents=True, exist_ok=True)

    badge_colors = {
        "CRITICAL": "background:#7f1d1d;color:#fecaca;border:1px solid #ef4444;",
        "HIGH": "background:#7c2d12;color:#fed7aa;border:1px solid #f97316;",
        "MEDIUM": "background:#78350f;color:#fde68a;border:1px solid #f59e0b;",
        "LOW": "background:#064e3b;color:#a7f3d0;border:1px solid #10b981;",
    }

    rows_html = []
    for a in report.alerts:
        style = badge_colors.get(a.severity, "")
        rows_html.append(
            f"""
            <tr>
              <td><span style="padding:3px 8px;border-radius:6px;font-size:11px;font-weight:700;{style}">{html.escape(a.severity)}</span></td>
              <td style="font-family:monospace;color:#93c5fd;">{html.escape(a.rule_id)}</td>
              <td><strong>{html.escape(a.title)}</strong><br><span style="color:#94a3b8;font-size:12px;">{html.escape(a.evidence)}</span></td>
              <td style="font-family:monospace;font-size:12px;color:#c4b5fd;">{html.escape(a.mitre_technique)}</td>
              <td style="font-family:monospace;font-size:12px;">{html.escape(a.host)}<br><span style="color:#94a3b8;">{html.escape(a.source_ip)}</span></td>
              <td style="font-size:12px;color:#cbd5e1;">{html.escape(a.remediation)}</td>
            </tr>
            """
        )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>SOC Log Sentinel | Security Triage Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#0b0f19; color:#e2e8f0; margin:0; padding:32px; }}
    .container {{ max-width:1200px; margin:0 auto; }}
    .header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1e293b; padding-bottom:20px; margin-bottom:24px; }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:28px; }}
    .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px; padding:18px; }}
    .card-label {{ font-size:11px; text-transform:uppercase; color:#94a3b8; letter-spacing:0.05em; }}
    .card-value {{ font-size:28px; font-weight:800; margin-top:6px; }}
    table {{ width:100%; border-collapse:collapse; background:#111827; border:1px solid #1f2937; border-radius:12px; overflow:hidden; }}
    th, td {{ text-align:left; padding:14px 16px; border-bottom:1px solid #1f2937; vertical-align:top; }}
    th {{ background:#0f172a; font-size:11px; text-transform:uppercase; color:#94a3b8; letter-spacing:0.05em; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 style="margin:0;font-size:24px;">SOC Log Sentinel — Incident Triage Report</h1>
        <p style="margin:6px 0 0;font-size:13px;color:#94a3b8;">Source: {html.escape(report.input_file)} • Generated: {html.escape(report.generated_at)}</p>
      </div>
      <div style="text-align:right;">
        <div style="font-size:11px;color:#94a3b8;">OVERALL POSTURE</div>
        <div style="font-size:20px;font-weight:800;color:#f87171;">{html.escape(report.risk_level)} ({report.risk_score}/100)</div>
      </div>
    </div>

    <div class="cards">
      <div class="card"><div class="card-label">Events Analyzed</div><div class="card-value">{report.total_events}</div></div>
      <div class="card"><div class="card-label">Correlated Alerts</div><div class="card-value" style="color:#818cf8;">{report.total_alerts}</div></div>
      <div class="card"><div class="card-label">Critical Alerts</div><div class="card-value" style="color:#f87171;">{report.severity_counts.get('CRITICAL', 0)}</div></div>
      <div class="card"><div class="card-label">Affected Hosts</div><div class="card-value" style="color:#38bdf8;">{len(report.affected_hosts)}</div></div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule</th>
          <th>Detection & Evidence</th>
          <th>MITRE ATT&CK</th>
          <th>Host / IP</th>
          <th>Recommended Remediation</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows_html) if rows_html else '<tr><td colspan="6" style="text-align:center;color:#94a3b8;">No threats detected.</td></tr>'}
      </tbody>
    </table>
  </div>
</body>
</html>
"""
    with out_path.open("w", encoding="utf-8") as f:
        f.write(html_doc)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Log Sentinel: Zero-dependency threat detection & MITRE ATT&CK triage engine."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/sample_security_events.json"),
        help="Path to JSON, CSV, or Linux auth.log file.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("output"),
        help="Directory to write report.json and report.html.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=4,
        help="Failed logon threshold for brute-force detection (default: 4).",
    )
    args = parser.parse_args()

    events = load_events(args.input)
    alerts = detect_threats(events, brute_force_threshold=args.threshold)
    report = build_report(events, alerts, str(args.input))

    json_path = args.out_dir / "report.json"
    html_path = args.out_dir / "report.html"
    export_json(report, json_path)
    export_html(report, html_path)

    print("=" * 68)
    print(f"SOC LOG SENTINEL | Posture: {report.risk_level} ({report.risk_score}/100)")
    print(f"Events Analyzed: {report.total_events} | Alerts Triggered: {report.total_alerts}")
    print("=" * 68)
    for alert in report.alerts:
        print(f"[{alert.severity:8}] {alert.rule_id} | {alert.mitre_technique} | {alert.title}")
        print(f"           Host: {alert.host} | IP: {alert.source_ip} | User: {alert.user}")
    print("-" * 68)
    print(f"JSON Report: {json_path}")
    print(f"HTML Report: {html_path}")


if __name__ == "__main__":
    main()
