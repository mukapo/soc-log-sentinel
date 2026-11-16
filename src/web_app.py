"""
SOC Log Sentinel - Interactive Local Web SIEM Console.
Zero-dependency HTTP server powered by Python stdlib.

Usage:
    python3 src/web_app.py
    Open http://127.0.0.1:8080 in your browser.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from detector import build_report, detect_threats, parse_raw_text  # noqa: E402

HTML_UI = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SOC Log Sentinel | Interactive Triage Console</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; background: #070a12; color: #e2e8f0; }
    .mono { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="min-h-screen p-6 md:p-10">
  <div class="max-w-7xl mx-auto space-y-6">
    <!-- Header -->
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-6">
      <div>
        <div class="text-xs mono text-cyan-400 uppercase tracking-wider">SOC Log Sentinel v1.0 • @mukapo</div>
        <h1 class="text-2xl md:text-3xl font-extrabold text-white mt-1">Interactive SIEM & MITRE ATT&CK Triage Console</h1>
      </div>
      <div class="flex flex-wrap gap-2">
        <button onclick="loadSample('windows')" class="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition">Load Windows AD Attack</button>
        <button onclick="loadSample('linux')" class="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition">Load Linux SSH + Sudo Attack</button>
      </div>
    </div>

    <!-- Input Panel -->
    <div class="bg-[#0d1322] border border-gray-800 rounded-2xl p-5 space-y-3">
      <div class="flex items-center justify-between">
        <label class="text-xs mono text-gray-400 uppercase">Raw Security Logs (JSON / CSV / Linux auth.log)</label>
        <input type="file" id="file-input" class="text-xs text-gray-400" onchange="handleFileUpload(event)" />
      </div>
      <textarea id="log-input" rows="5" class="w-full bg-[#070a12] border border-gray-800 rounded-xl p-3 text-xs mono text-gray-200 focus:outline-none focus:border-indigo-500" placeholder="Paste raw Windows Event JSON/CSV or Linux /var/log/auth.log lines here..."></textarea>
      <div class="flex items-center justify-between">
        <span class="text-xs text-gray-500">Zero-dependency Python 3 correlation engine • Instant MITRE mapping</span>
        <button onclick="analyzeLogs()" class="px-5 py-2.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-gray-950 font-bold text-xs transition">Analyze Threat Logs</button>
      </div>
    </div>

    <!-- KPI Cards -->
    <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
      <div class="bg-[#0d1322] border border-gray-800 rounded-2xl p-4">
        <div class="text-[11px] text-gray-400 uppercase">Risk Posture</div>
        <div id="kpi-posture" class="text-2xl font-extrabold text-white mt-1 mono">--</div>
      </div>
      <div class="bg-[#0d1322] border border-gray-800 rounded-2xl p-4">
        <div class="text-[11px] text-gray-400 uppercase">Events Parsed</div>
        <div id="kpi-events" class="text-2xl font-extrabold text-white mt-1 mono">0</div>
      </div>
      <div class="bg-[#0d1322] border border-gray-800 rounded-2xl p-4">
        <div class="text-[11px] text-gray-400 uppercase">Total Alerts</div>
        <div id="kpi-alerts" class="text-2xl font-extrabold text-indigo-400 mt-1 mono">0</div>
      </div>
      <div class="bg-[#0d1322] border border-gray-800 rounded-2xl p-4">
        <div class="text-[11px] text-gray-400 uppercase">Critical</div>
        <div id="kpi-critical" class="text-2xl font-extrabold text-red-400 mt-1 mono">0</div>
      </div>
      <div class="bg-[#0d1322] border border-gray-800 rounded-2xl p-4">
        <div class="text-[11px] text-gray-400 uppercase">Top Attacker IP</div>
        <div id="kpi-topip" class="text-sm font-bold text-amber-400 mt-2 mono">--</div>
      </div>
    </div>

    <!-- Alerts Table -->
    <div class="bg-[#0d1322] border border-gray-800 rounded-2xl overflow-hidden">
      <div class="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
        <h2 class="text-sm font-bold text-white">Correlated Incident Queue</h2>
        <select id="sev-filter" onchange="renderTable()" class="bg-[#070a12] border border-gray-700 rounded-lg px-2.5 py-1 text-xs text-gray-300">
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
        </select>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-[#070a12] text-[11px] text-gray-400 uppercase border-b border-gray-800">
              <th class="p-3.5">Severity</th>
              <th class="p-3.5">Rule & Detection</th>
              <th class="p-3.5">MITRE ATT&CK</th>
              <th class="p-3.5">Host / IP / User</th>
              <th class="p-3.5">Triage Status</th>
            </tr>
          </thead>
          <tbody id="alerts-body" class="text-xs divide-y divide-gray-800">
            <tr><td colspan="5" class="p-6 text-center text-gray-500">Load a sample attack scenario or paste logs above to begin triage.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    let currentAlerts = [];
    const statusMap = {};

    async function loadSample(type) {
      const res = await fetch('/api/sample?type=' + type);
      const data = await res.json();
      document.getElementById('log-input').value = data.raw;
      await analyzeLogs();
    }

    function handleFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (ev) => {
        document.getElementById('log-input').value = ev.target.result;
        analyzeLogs();
      };
      reader.readAsText(file);
    }

    async function analyzeLogs() {
      const raw = document.getElementById('log-input').value;
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw })
      });
      const report = await res.json();
      if (report.error) { alert(report.error); return; }

      document.getElementById('kpi-posture').textContent = `${report.risk_level} (${report.risk_score})`;
      document.getElementById('kpi-events').textContent = report.total_events;
      document.getElementById('kpi-alerts').textContent = report.total_alerts;
      document.getElementById('kpi-critical').textContent = report.severity_counts.CRITICAL || 0;
      document.getElementById('kpi-topip').textContent = report.top_source_ips.length ? `${report.top_source_ips[0].ip} (${report.top_source_ips[0].alerts})` : 'None';

      currentAlerts = report.alerts || [];
      renderTable();
    }

    function cycleStatus(idx) {
      const states = ['OPEN', 'INVESTIGATING', 'RESOLVED'];
      const cur = statusMap[idx] || 'OPEN';
      statusMap[idx] = states[(states.indexOf(cur) + 1) % states.length];
      renderTable();
    }

    function renderTable() {
      const filter = document.getElementById('sev-filter').value;
      const tbody = document.getElementById('alerts-body');
      const filtered = currentAlerts.filter(a => filter === 'ALL' || a.severity === filter);
      if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-gray-500">No alerts match current filter.</td></tr>';
        return;
      }
      const badge = {
        CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
        HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
        MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/30'
      };
      const stBadge = {
        OPEN: 'bg-red-500/10 text-red-300 border-red-500/20',
        INVESTIGATING: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20',
        RESOLVED: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20'
      };

      tbody.innerHTML = filtered.map((a, idx) => {
        const st = statusMap[idx] || 'OPEN';
        return `<tr class="hover:bg-white/[0.02]">
          <td class="p-3.5"><span class="px-2 py-0.5 rounded border text-[10px] font-bold ${badge[a.severity] || ''}">${a.severity}</span></td>
          <td class="p-3.5"><div class="font-semibold text-white">${a.rule_id}: ${a.title}</div><div class="text-gray-400 mt-0.5">${a.evidence}</div><div class="text-emerald-400/90 mt-1 text-[11px]">Fix: ${a.remediation}</div></td>
          <td class="p-3.5 mono text-purple-300">${a.mitre_technique}</td>
          <td class="p-3.5 mono text-gray-300">${a.host}<br><span class="text-cyan-400">${a.source_ip}</span><br><span class="text-gray-500">user: ${a.user}</span></td>
          <td class="p-3.5"><button onclick="cycleStatus(${idx})" class="px-2.5 py-1 rounded border text-[10px] mono ${stBadge[st]}">${st}</button></td>
        </tr>`;
      }).join('');
    }
  </script>
</body>
</html>
"""


class SocHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/index"):
            body = HTML_UI.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/sample"):
            sample_file = (
                BASE_DIR / "data" / "sample_linux_auth.log"
                if "linux" in self.path
                else BASE_DIR / "data" / "sample_security_events.json"
            )
            self._send_json({"raw": sample_file.read_text(encoding="utf-8")})
        else:
            self._send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        if self.path == "/api/analyze":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                events = parse_raw_text(data.get("raw", ""))
                alerts = detect_threats(events)
                report = build_report(events, alerts, "web-console-input")
                self._send_json(asdict(report))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
        else:
            self._send_json({"error": "Not found"}, status=404)


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = HTTPServer((host, port), SocHandler)
    print(f"SOC Log Sentinel Web Console running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
