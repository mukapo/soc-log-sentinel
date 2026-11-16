"""
SOC Log Sentinel - Full End-to-End Interactive SIEM & Incident Management Console.
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
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from detector import (  # noqa: E402
    build_report,
    detect_threats,
    export_html,
    export_json,
    load_macos_live_logs,
    parse_raw_text,
)

HTML_UI = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SOC Log Sentinel | Command & Triage Console</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; background: #070a12; color: #e2e8f0; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    .card { background: #0d1322; border: 1px solid #1e293b; border-radius: 1rem; }
  </style>
</head>
<body class="min-h-screen p-4 md:p-8">
  <div id="toast" class="fixed bottom-5 right-5 z-50 hidden px-4 py-2.5 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs mono shadow-xl"></div>

  <div class="max-w-7xl mx-auto space-y-6">
    <!-- Top Bar -->
    <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-gray-800 pb-5">
      <div>
        <div class="flex items-center gap-2 text-xs mono text-cyan-400">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>SOC LOG SENTINEL v1.0 • FULL TRIAGE & RESPONSE CONSOLE</span>
        </div>
        <h1 class="text-2xl md:text-3xl font-extrabold text-white mt-1">Security Operations & MITRE ATT&CK Control Center</h1>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <button onclick="runLiveMacOS()" class="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition flex items-center gap-1.5">
          <span>⚡ Scan Live macOS</span>
        </button>
        <button onclick="exportReport('html')" class="px-3.5 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 text-xs font-semibold transition">Export HTML</button>
        <button onclick="exportReport('json')" class="px-3.5 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 text-xs font-semibold transition">Export JSON</button>
      </div>
    </div>

    <!-- Ingestion & Scenario Controls -->
    <div class="card p-5 space-y-4">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-xs mono text-gray-400 mr-1">Scenarios:</span>
          <button onclick="loadSample('windows')" class="px-3 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/40 border border-indigo-500/30 text-indigo-300 text-xs font-medium transition">Windows AD Attack</button>
          <button onclick="loadSample('linux')" class="px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/40 border border-cyan-500/30 text-cyan-300 text-xs font-medium transition">Linux SSH + Sudo</button>
          <button onclick="loadSample('web')" class="px-3 py-1.5 rounded-lg bg-purple-600/20 hover:bg-purple-600/40 border border-purple-500/30 text-purple-300 text-xs font-medium transition">Web SQLi / Log4j</button>
          <button onclick="loadSample('openssh_real')" class="px-3 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/40 border border-amber-500/30 text-amber-300 text-xs font-medium transition">Real LabSZ (2k Lines)</button>
        </div>
        <div class="flex items-center gap-3">
          <label class="text-xs text-gray-400">Brute-Force Threshold:
            <input id="threshold-input" type="number" value="4" min="2" max="50" class="w-14 ml-1 bg-[#070a12] border border-gray-700 rounded px-2 py-1 text-xs mono text-white" />
          </label>
          <input type="file" id="file-input" class="text-xs text-gray-400 max-w-[180px]" onchange="handleFileUpload(event)" />
        </div>
      </div>

      <textarea id="log-input" rows="5" class="w-full bg-[#070a12] border border-gray-800 rounded-xl p-3 text-xs mono text-gray-200 focus:outline-none focus:border-indigo-500" placeholder="Paste Windows JSON/CSV, Linux auth.log, or Nginx/Apache HTTP access logs here..."></textarea>

      <div class="flex items-center justify-between">
        <span id="source-status" class="text-xs mono text-gray-500">Ready • Supports JSON, CSV, Linux auth.log, OpenSSH, Nginx/Apache</span>
        <button onclick="analyzeLogs()" class="px-6 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs transition shadow-lg shadow-indigo-600/25">Run Threat Analysis</button>
      </div>
    </div>

    <!-- KPI Row -->
    <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
      <div class="card p-4">
        <div class="text-[11px] text-gray-400 uppercase">Risk Posture</div>
        <div id="kpi-posture" class="text-xl font-extrabold text-white mt-1 mono">--</div>
      </div>
      <div class="card p-4">
        <div class="text-[11px] text-gray-400 uppercase">Events Parsed</div>
        <div id="kpi-events" class="text-2xl font-extrabold text-white mt-1 mono">0</div>
      </div>
      <div class="card p-4">
        <div class="text-[11px] text-gray-400 uppercase">Total Alerts</div>
        <div id="kpi-alerts" class="text-2xl font-extrabold text-indigo-400 mt-1 mono">0</div>
      </div>
      <div class="card p-4">
        <div class="text-[11px] text-gray-400 uppercase">Critical / High</div>
        <div id="kpi-crithigh" class="text-2xl font-extrabold text-red-400 mt-1 mono">0 / 0</div>
      </div>
      <div class="card p-4">
        <div class="text-[11px] text-gray-400 uppercase">Affected Hosts</div>
        <div id="kpi-hosts" class="text-2xl font-extrabold text-cyan-400 mt-1 mono">0</div>
      </div>
    </div>

    <!-- Analytics Row: MITRE Matrix + Top Attacking IPs -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-5">
      <div class="lg:col-span-7 card p-5">
        <div class="text-xs mono text-gray-400 uppercase mb-3">MITRE ATT&CK Tactics Triggered</div>
        <div id="mitre-grid" class="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
          <div class="p-2.5 rounded-lg bg-[#070a12] border border-gray-800 text-gray-500">Initial Access</div>
          <div class="p-2.5 rounded-lg bg-[#070a12] border border-gray-800 text-gray-500">Credential Access</div>
          <div class="p-2.5 rounded-lg bg-[#070a12] border border-gray-800 text-gray-500">Execution</div>
          <div class="p-2.5 rounded-lg bg-[#070a12] border border-gray-800 text-gray-500">Persistence</div>
          <div class="p-2.5 rounded-lg bg-[#070a12] border border-gray-800 text-gray-500">Privilege Escalation</div>
          <div class="p-2.5 rounded-lg bg-[#070a12] border border-gray-800 text-gray-500">Defense Evasion</div>
        </div>
      </div>

      <div class="lg:col-span-5 card p-5">
        <div class="text-xs mono text-gray-400 uppercase mb-3">Top Attacking IPs & 1-Click Firewall Block</div>
        <div id="top-ips" class="space-y-2 text-xs text-gray-400">
          <div>Run an analysis to see attacking source IPs.</div>
        </div>
      </div>
    </div>

    <!-- Incident Triage Queue -->
    <div class="card overflow-hidden">
      <div class="px-5 py-4 border-b border-gray-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <h2 class="text-sm font-bold text-white">Incident Triage & Response Queue</h2>
        <div class="flex items-center gap-2">
          <input id="search-box" type="text" oninput="renderTable()" placeholder="Search IP, user, MITRE..." class="bg-[#070a12] border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500" />
          <select id="sev-filter" onchange="renderTable()" class="bg-[#070a12] border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-300">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
          </select>
        </div>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="bg-[#070a12] text-[11px] text-gray-400 uppercase border-b border-gray-800">
              <th class="p-3.5">Severity</th>
              <th class="p-3.5">Rule & Detection</th>
              <th class="p-3.5">MITRE ATT&CK</th>
              <th class="p-3.5">Host / IP / User</th>
              <th class="p-3.5">Status</th>
            </tr>
          </thead>
          <tbody id="alerts-body" class="text-xs divide-y divide-gray-800">
            <tr><td colspan="5" class="p-6 text-center text-gray-500">Select a scenario above or click "Scan Live macOS" to begin.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    let currentReport = null;
    let currentAlerts = [];
    const statusMap = {};

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.remove('hidden');
      setTimeout(() => t.classList.add('hidden'), 2800);
    }

    async function loadSample(type) {
      const res = await fetch('/api/sample?type=' + type);
      const data = await res.json();
      if (data.error) { showToast(data.error); return; }
      document.getElementById('log-input').value = data.raw;
      document.getElementById('source-status').textContent = 'Loaded scenario: ' + type;
      await analyzeLogs();
    }

    async function runLiveMacOS() {
      document.getElementById('source-status').textContent = 'Querying live macOS Unified Logs...';
      const res = await fetch('/api/live-macos');
      const report = await res.json();
      if (report.error) { alert('Live macOS scan error: ' + report.error); return; }
      applyReport(report);
      showToast('Live macOS scan complete!');
    }

    function handleFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (ev) => {
        document.getElementById('log-input').value = ev.target.result;
        document.getElementById('source-status').textContent = 'Loaded file: ' + file.name;
        analyzeLogs();
      };
      reader.readAsText(file);
    }

    async function analyzeLogs() {
      const raw = document.getElementById('log-input').value;
      const threshold = parseInt(document.getElementById('threshold-input').value || '4', 10);
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw, threshold })
      });
      const report = await res.json();
      if (report.error) { alert(report.error); return; }
      applyReport(report);
    }

    function applyReport(report) {
      currentReport = report;
      currentAlerts = report.alerts || [];

      document.getElementById('kpi-posture').textContent = `${report.risk_level} (${report.risk_score})`;
      document.getElementById('kpi-events').textContent = report.total_events;
      document.getElementById('kpi-alerts').textContent = report.total_alerts;
      document.getElementById('kpi-crithigh').textContent = `${report.severity_counts.CRITICAL || 0} / ${report.severity_counts.HIGH || 0}`;
      document.getElementById('kpi-hosts').textContent = (report.affected_hosts || []).length;

      // Update MITRE Tactics Grid
      const tactics = ['Initial Access', 'Credential Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Reconnaissance'];
      const activeTactics = currentAlerts.map(a => a.mitre_tactic);
      document.getElementById('mitre-grid').innerHTML = tactics.map(t => {
        const hit = activeTactics.some(at => at.includes(t));
        return hit
          ? `<div class="p-2.5 rounded-lg bg-red-500/15 border border-red-500/40 text-red-300 font-semibold flex items-center justify-between"><span>${t}</span><span class="text-[10px] mono">HIT</span></div>`
          : `<div class="p-2.5 rounded-lg bg-[#070a12] border border-gray-800 text-gray-500">${t}</div>`;
      }).join('');

      // Update Top IPs
      const ipsDiv = document.getElementById('top-ips');
      if (!report.top_source_ips || !report.top_source_ips.length) {
        ipsDiv.innerHTML = '<div class="text-gray-500">No external attacking IPs detected.</div>';
      } else {
        ipsDiv.innerHTML = report.top_source_ips.map(item => `
          <div class="flex items-center justify-between bg-[#070a12] border border-gray-800 rounded-lg px-3 py-2">
            <div><span class="mono text-cyan-300 font-semibold">${item.ip}</span> <span class="text-gray-500 ml-2">(${item.alerts} alerts)</span></div>
            <button onclick="copyBlockCmd('${item.ip}')" class="px-2.5 py-1 rounded bg-red-500/15 hover:bg-red-500/30 border border-red-500/30 text-red-300 text-[10px] mono transition">Copy Block Cmd</button>
          </div>
        `).join('');
      }

      renderTable();
    }

    function copyBlockCmd(ip) {
      const cmd = `sudo ufw deny from ${ip} to any # SOC Log Sentinel Block`;
      navigator.clipboard.writeText(cmd);
      showToast('Copied firewall block rule: ' + cmd);
    }

    function exportReport(fmt) {
      if (!currentReport) { showToast('Run an analysis first!'); return; }
      window.open('/api/export?fmt=' + fmt, '_blank');
    }

    function cycleStatus(idx) {
      const states = ['OPEN', 'INVESTIGATING', 'RESOLVED'];
      const cur = statusMap[idx] || 'OPEN';
      statusMap[idx] = states[(states.indexOf(cur) + 1) % states.length];
      renderTable();
    }

    function renderTable() {
      const filter = document.getElementById('sev-filter').value;
      const q = (document.getElementById('search-box').value || '').toLowerCase();
      const tbody = document.getElementById('alerts-body');
      const filtered = currentAlerts.filter(a => {
        const sevOk = filter === 'ALL' || a.severity === filter;
        const text = `${a.rule_id} ${a.title} ${a.source_ip} ${a.user} ${a.host} ${a.mitre_technique}`.toLowerCase();
        return sevOk && (!q || text.includes(q));
      });

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
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path in {"/", "/index.html"}:
            body = HTML_UI.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/api/sample":
            kind = params.get("type", ["windows"])[0]
            mapping = {
                "windows": BASE_DIR / "data" / "sample_security_events.json",
                "linux": BASE_DIR / "data" / "sample_linux_auth.log",
                "web": BASE_DIR / "data" / "sample_web_access.log",
                "openssh_real": BASE_DIR / "data" / "real_openssh_2k.log",
            }
            target = mapping.get(kind, mapping["windows"])
            if not target.exists():
                self._send_json({"error": f"Dataset not found locally: {target.name}"}, status=404)
                return
            self._send_json({"raw": target.read_text(encoding="utf-8")})
        elif parsed.path == "/api/live-macos":
            try:
                events = load_macos_live_logs(hours=24)
                alerts = detect_threats(events)
                report = build_report(events, alerts, "macOS Live Unified Logs (24h)")
                export_json(report, BASE_DIR / "output" / "report.json")
                export_html(report, BASE_DIR / "output" / "report.html")
                self._send_json(asdict(report))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
        elif parsed.path == "/api/export":
            fmt = params.get("fmt", ["html"])[0]
            target = BASE_DIR / "output" / ("report.json" if fmt == "json" else "report.html")
            if not target.exists():
                self._send_json({"error": "No report exported yet."}, status=404)
                return
            body = target.read_bytes()
            ctype = "application/json" if fmt == "json" else "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json({"error": "Not found"}, status=404)

    def do_POST(self) -> None:
        if self.path == "/api/analyze":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                threshold = int(data.get("threshold", 4))
                events = parse_raw_text(data.get("raw", ""))
                alerts = detect_threats(events, brute_force_threshold=threshold)
                report = build_report(events, alerts, "web-console-input")
                export_json(report, BASE_DIR / "output" / "report.json")
                export_html(report, BASE_DIR / "output" / "report.html")
                self._send_json(asdict(report))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
        else:
            self._send_json({"error": "Not found"}, status=404)


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = HTTPServer((host, port), SocHandler)
    print(f"SOC Log Sentinel Control Center running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
