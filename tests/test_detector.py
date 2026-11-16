"""Unit tests for SOC Log Sentinel detection engine and log parsers."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from detector import build_report, detect_threats, parse_raw_text


class TestSocDetector(unittest.TestCase):
    def test_detects_post_brute_force_compromise(self) -> None:
        events = [
            {"timestamp": "2026-11-16T09:00:01Z", "host": "DC-01", "event_id": 4625, "user": "alice", "source_ip": "1.2.3.4"},
            {"timestamp": "2026-11-16T09:00:02Z", "host": "DC-01", "event_id": 4625, "user": "alice", "source_ip": "1.2.3.4"},
            {"timestamp": "2026-11-16T09:00:03Z", "host": "DC-01", "event_id": 4625, "user": "alice", "source_ip": "1.2.3.4"},
            {"timestamp": "2026-11-16T09:00:04Z", "host": "DC-01", "event_id": 4625, "user": "alice", "source_ip": "1.2.3.4"},
            {"timestamp": "2026-11-16T09:00:05Z", "host": "DC-01", "event_id": 4624, "user": "alice", "source_ip": "1.2.3.4"},
        ]
        alerts = detect_threats(events, brute_force_threshold=4)
        rule_ids = {a.rule_id for a in alerts}
        self.assertIn("SOC-001", rule_ids)
        self.assertIn("SOC-002", rule_ids)

    def test_detects_privilege_escalation_and_log_clear(self) -> None:
        events = [
            {"timestamp": "2026-11-16T09:05:00Z", "host": "DC-01", "event_id": 4720, "user": "bad_user", "actor": "alice", "source_ip": "1.2.3.4"},
            {"timestamp": "2026-11-16T09:06:00Z", "host": "DC-01", "event_id": 4732, "user": "bad_user", "actor": "alice", "group": "Administrators", "source_ip": "1.2.3.4"},
            {"timestamp": "2026-11-16T09:07:00Z", "host": "DC-01", "event_id": 1102, "user": "bad_user", "source_ip": "127.0.0.1"},
        ]
        alerts = detect_threats(events)
        rule_ids = {a.rule_id for a in alerts}
        self.assertEqual(rule_ids, {"SOC-003", "SOC-004", "SOC-005"})

    def test_detects_encoded_powershell(self) -> None:
        events = [
            {
                "timestamp": "2026-11-16T09:08:00Z",
                "host": "WS-05",
                "event_id": 4688,
                "user": "bob",
                "source_ip": "10.0.0.5",
                "command_line": "powershell.exe -enc SQBFAFgA",
            }
        ]
        alerts = detect_threats(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "SOC-006")

    def test_linux_auth_log_spray_and_sudo_escalation(self) -> None:
        raw_log = "\n".join([
            "Nov 16 09:14:01 web-01 sshd[10]: Failed password for invalid user admin from 9.9.9.9 port 111 ssh2",
            "Nov 16 09:14:02 web-01 sshd[11]: Failed password for invalid user root from 9.9.9.9 port 112 ssh2",
            "Nov 16 09:14:03 web-01 sshd[12]: Failed password for invalid user postgres from 9.9.9.9 port 113 ssh2",
            "Nov 16 09:16:02 web-01 sudo[15]: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo backdoor",
        ])
        events = parse_raw_text(raw_log)
        alerts = detect_threats(events)
        rule_ids = {a.rule_id for a in alerts}
        self.assertIn("SOC-008", rule_ids)
        self.assertIn("SOC-007", rule_ids)

    def test_clean_traffic_returns_low_risk(self) -> None:
        events = [
            {"timestamp": "2026-11-16T08:00:00Z", "host": "WS-01", "event_id": 4624, "user": "bob", "source_ip": "10.0.0.2"}
        ]
        alerts = detect_threats(events)
        report = build_report(events, alerts, "clean.json")
        self.assertEqual(report.total_alerts, 0)
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(report.risk_level, "LOW")


if __name__ == "__main__":
    unittest.main()
