"""
SOC Log Sentinel - Real-Workflow SIEM & Incident Management Console.
Features persistent incident triage (saved to disk), real IP/DNS enrichment,
live macOS log scanning, and dynamic open-risk recalculation.

Usage:
    python3 src/web_app.py
    Open http://127.0.0.1:8080 in your browser.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
STATE_FILE = BASE_DIR / "output" / "incidents_state.json"
sys.path.insert(0, str(Path(__file__).resolve().parent))

from detector import (  # noqa: E402
    SEVERITY_WEIGHTS,
    build_report,
    detect_threats,
    export_html,
    export_json,
    load_macos_live_logs,
    parse_raw_text,
)


def load_triage_state() -> dict[str, dict[str, str]]:
    """Load persisted analyst triage statuses and notes from disk."""
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_triage_state(state: dict[str, dict[str, str]]) -> None:
    """Persist analyst triage statuses and notes to disk."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def enrich_ip(ip_str: str) -> dict[str, str]:
    """Perform real local IP classification and Reverse DNS lookup."""
    result = {"ip": ip_str, "scope": "Unknown", "rdns": "No PTR record"}
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:
            result["scope"] = "Loopback (Localhost)"
        elif ip_obj.is_private:
            result["scope"] = "Private Internal Network (RFC1918)"
        else:
            result["scope"] = "Public External Internet"
            try:
                socket.setdefaulttimeout(1.5)
                host, _, _ = socket.gethostbyaddr(ip_str)
                result["rdns"] = host
            except Exception:
                result["rdns"] = "Unresolved / No PTR"
    except ValueError:
        result["scope"] = "Hostname / Non-IP String"
    return result


HTML_UI = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SOC Log Sentinel | Incident Response Console</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; background: #060911; color: #e2e8f0; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    .panel { background: #0c1220; border: 1px solid #1e293b; border-radius: 14px; }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
  </style>
</head>
<body class="min-h-screen flex flex-col lg:flex-row">

  <!-- Toast -->
  <div id="toast" class="fixed bottom-5 right-5 z-50 hidden px-4 py-2.5 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs mono shadow-2xl backdrop-blur-md"></div>

  <!-- Left Sidebar: Ingestion & Controls -->
  <aside class="w-full lg:w-80 shrink-0 bg-[#090e1a] border-b lg:border-b-0 lg:border-r border-gray-800/90 p-5 flex flex-col justify-between gap-6">
    <div class="space-y-6">
      <!-- Brand -->
      <div>
        <div class="flex items-center gap-2 text-[11px] mono text-cyan-400">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>SOC LOG SENTINEL</span>
        </div>
        <h1 class="text-lg font-extrabold text-white mt-1">Incident Control Center</h1>
        <p class="text-xs text-gray-400 mt-1">Zero-dependency SIEM & persistent triage workflow.</p>
      </div>

      <!-- Data Sources -->
      <div class="space-y-2.5">
        <div class="text-[11px] mono text-gray-400 uppercase tracking-wider">1. Log Source</div>
        <button onclick="runLiveMacOS()" class="w-full py-2.5 px-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold transition text-left flex items-center justify-between">
          <span>⚡ Scan Live macOS Logs</span>
          <span class="text-[10px] mono bg-black/25 px-1.5 py-0.5 rounded">LIVE</span>
        </button>

        <div class="grid grid-cols-2 gap-2 pt-1">
          <button onclick="loadSample('windows')" class="py-2 px-2.5 rounded-lg bg-[#0c1220] hover:bg-gray-800 border border-gray-800 text-xs text-indigo-300 text-left transition">Windows AD</button>
          <button onclick="loadSample('linux')" class="py-2 px-2.5 rounded-lg bg-[#0c1220] hover:bg-gray-800 border border-gray-800 text-xs text-cyan-300 text-left transition">Linux SSH</button>
          <button onclick="loadSample('web')" class="py-2 px-2.5 rounded-lg bg-[#0c1220] hover:bg-gray-800 border border-gray-800 text-xs text-purple-300 text-left transition">Web Attacks</button>
          <button onclick="loadSample('openssh_real')" class="py-2 px-2.5 rounded-lg bg-[#0c1220] hover:bg-gray-800 border border-gray-800 text-xs text-amber-300 text-left transition">LabSZ (2k)</button>
        </div>

        <label class="block pt-2">
          <span class="text-[11px] text-gray-400">Or Upload Log File (.json, .csv, .log):</span>
          <input type="file" id="file-input" onchange="handleFileUpload(event)" class="mt-1 block w-full text-xs text-gray-400 file:mr-2 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-gray-800 file:text-gray-200 hover:file:bg-gray-700" />
        </label>
      </div>

      <!-- Raw Log Input & Threshold -->
      <div class="space-y-2.5">
        <div class="flex items-center justify-between">
          <span class="text-[11px] mono text-gray-400 uppercase">2. Raw Payload</span>
          <label class="text-[11px] text-gray-400">Threshold:
            <input id="threshold-input" type="number" value="4" min="2" max="50" class="w-12 ml-1 bg-[#060911] border border-gray-700 rounded px-1.5 py-0.5 text-xs mono text-white" />
          </label>
        </div>
        <textarea id="log-input" rows="5" class="w-full bg-[#060911] border border-gray-800 rounded-xl p-2.5 text-[11px] mono text-gray-300 focus:outline-none focus:border-indigo-500" placeholder="Paste raw logs here..."></textarea>
        <button onclick="analyzeLogs()" class="w-full py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs transition shadow-lg shadow-indigo-600/20">
          Analyze Logs
        </button>
      </div>
    </div>

    <!-- Export Actions -->
    <div class="pt-4 border-t border-gray-800 space-y-2">
      <div class="text-[11px] mono text-gray-400 uppercase">3. Export Audit Reports</div>
      <div class="grid grid-cols-2 gap-2">
        <button onclick="exportReport('html')" class="py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-xs font-semibold text-gray-200 transition">HTML Report</button>
        <button onclick="exportReport('json')" class="py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-xs font-semibold text-gray-200 transition">JSON (SOAR)</button>
      </div>
    </div>
  </aside>

  <!-- Main Workspace -->
  <main class="flex-1 p-5 lg:p-8 space-y-6 overflow-y-auto">

    <!-- KPI Strip -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
      <div class="panel p-4">
        <div class="text-[11px] text-gray-400 uppercase">Active Open Risk</div>
        <div id="kpi-posture" class="text-2xl font-extrabold text-white mt-1 mono">--</div>
        <div id="kpi-sub" class="text-[11px] text-gray-500 mt-1">Select a log source</div>
      </div>
      <div class="panel p-4">
        <div class="text-[11px] text-gray-400 uppercase">Events Analyzed</div>
        <div id="kpi-events" class="text-2xl font-extrabold text-white mt-1 mono">0</div>
        <div class="text-[11px] text-gray-500 mt-1">Normalized telemetry</div>
      </div>
      <div class="panel p-4">
        <div class="text-[11px] text-gray-400 uppercase">Open / Resolved</div>
        <div id="kpi-alerts" class="text-2xl font-extrabold text-indigo-400 mt-1 mono">0 / 0</div>
        <div class="text-[11px] text-gray-500 mt-1">Persisted in state DB</div>
      </div>
      <div class="panel p-4">
        <div class="text-[11px] text-gray-400 uppercase">Top Attacker IP</div>
        <div id="kpi-topip" class="text-sm font-bold text-amber-400 mt-2 mono truncate">--</div>
        <div class="text-[11px] text-gray-500 mt-1">Highest alert volume</div>
      </div>
    </div>

    <!-- MITRE ATT&CK Tactics Strip -->
    <div class="panel p-4">
      <div class="text-[11px] mono text-gray-400 uppercase mb-2.5">MITRE ATT&CK Coverage</div>
      <div id="mitre-grid" class="flex flex-wrap gap-2 text-xs">
        <span class="px-2.5 py-1 rounded-lg bg-[#060911] border border-gray-800 text-gray-500">Waiting for scan...</span>
      </div>
    </div>

    <!-- Incident Table -->
    <div class="panel overflow-hidden">
      <div class="px-5 py-3.5 border-b border-gray-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 class="text-sm font-bold text-white">Incident Triage Queue</h2>
          <p class="text-[11px] text-gray-400">Click any incident to open the Investigation Drawer (IP Lookup, Playbook & Persistent Resolution).</p>
        </div>
        <div class="flex items-center gap-2">
          <input id="search-box" type="text" oninput="renderTable()" placeholder="Filter IP, user, rule..." class="bg-[#060911] border border-gray-700 rounded-lg px-3 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-indigo-500" />
          <select id="sev-filter" onchange="renderTable()" class="bg-[#060911] border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-300">
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
            <tr class="bg-[#060911] text-[11px] text-gray-400 uppercase border-b border-gray-800">
              <th class="p-3.5">Severity</th>
              <th class="p-3.5">Incident & Evidence</th>
              <th class="p-3.5">MITRE ATT&CK</th>
              <th class="p-3.5">Host / IP</th>
              <th class="p-3.5">Workflow Status</th>
            </tr>
          </thead>
          <tbody id="alerts-body" class="text-xs divide-y divide-gray-800">
            <tr><td colspan="5" class="p-8 text-center text-gray-500">Choose a scenario in the left sidebar or scan your live macOS logs.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </main>

  <!-- Slide-Over Investigation Drawer -->
  <div id="drawer" class="fixed inset-0 z-50 hidden justify-end bg-black/75 backdrop-blur-sm">
    <div class="w-full max-w-lg bg-[#0c1220] border-l border-gray-800 h-full p-6 overflow-y-auto flex flex-col justify-between">
      <div class="space-y-5">
        <div class="flex items-start justify-between gap-4 border-b border-gray-800 pb-4">
          <div>
            <span id="dr-badge" class="px-2 py-0.5 rounded text-[10px] font-bold mono"></span>
            <h3 id="dr-title" class="text-lg font-bold text-white mt-2"></h3>
            <div id="dr-mitre" class="text-xs mono text-purple-300 mt-1"></div>
          </div>
          <button onclick="closeDrawer()" class="p-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs">✕</button>
        </div>

        <!-- Evidence -->
        <div class="space-y-1.5">
          <div class="text-[11px] mono text-gray-400 uppercase">Evidence Summary</div>
          <div id="dr-evidence" class="p-3 rounded-xl bg-[#060911] border border-gray-800 text-xs text-gray-200 leading-relaxed"></div>
        </div>

        <!-- Live IP Enrichment -->
        <div class="space-y-1.5">
          <div class="text-[11px] mono text-gray-400 uppercase">Live IP & Reverse DNS Enrichment</div>
          <div id="dr-enrich" class="p-3 rounded-xl bg-[#060911] border border-gray-800 text-xs mono text-cyan-300 space-y-1">
            Querying...
          </div>
        </div>

        <!-- Remediation Playbook & Firewall Command -->
        <div class="space-y-1.5">
          <div class="text-[11px] mono text-gray-400 uppercase">Recommended Remediation & Action</div>
          <div id="dr-remediation" class="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-200 leading-relaxed"></div>
          <button id="dr-block-btn" class="w-full py-2 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/30 text-red-300 text-xs mono transition">
            Copy Firewall Block Command
          </button>
        </div>

        <!-- Analyst Triage Persistence -->
        <div class="space-y-2.5 pt-2 border-t border-gray-800">
          <div class="text-[11px] mono text-gray-400 uppercase">Analyst Triage Decision (Saved to Disk)</div>
          <select id="dr-status" class="w-full bg-[#060911] border border-gray-700 rounded-lg px-3 py-2 text-xs text-white">
            <option value="OPEN">OPEN — Unreviewed</option>
            <option value="INVESTIGATING">INVESTIGATING — Active Triage</option>
            <option value="RESOLVED">RESOLVED — Mitigated / Closed</option>
          </select>
          <textarea id="dr-notes" rows="3" class="w-full bg-[#060911] border border-gray-700 rounded-lg p-2.5 text-xs text-gray-200" placeholder="Document investigation findings (e.g., Blocked IP on Edge Firewall, Verified false positive)..."></textarea>
        </div>
      </div>

      <div class="pt-4 border-t border-gray-800 flex items-center justify-end gap-2 mt-6">
        <button onclick="closeDrawer()" class="px-4 py-2 rounded-lg bg-gray-800 text-xs text-gray-300">Cancel</button>
        <button onclick="saveTriage()" class="px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold">Save Decision</button>
      </div>
    </div>
  </div>

  <script>
    let currentReport = null;
    let currentAlerts = [];
    let triageState = {};
    let activeAlertKey = null;

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.remove('hidden');
      setTimeout(() => t.classList.add('hidden'), 2800);
    }

    function alertKey(a) {
      return `${a.rule_id}|${a.host}|${a.source_ip}|${a.user}`;
    }

    async function loadSample(type) {
      const res = await fetch('/api/sample?type=' + type);
      const data = await res.json();
      if (data.error) { showToast(data.error); return; }
      document.getElementById('log-input').value = data.raw;
      await analyzeLogs();
    }

    async function runLiveMacOS() {
      document.getElementById('kpi-sub').textContent = 'Scanning live macOS logs...';
      const res = await fetch('/api/live-macos');
      const data = await res.json();
      if (data.error) { alert(data.error); return; }
      applyPayload(data);
      showToast('Live macOS Unified Logs analyzed!');
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
      const threshold = parseInt(document.getElementById('threshold-input').value || '4', 10);
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw, threshold })
      });
      const data = await res.json();
      if (data.error) { alert(data.error); return; }
      applyPayload(data);
    }

    function applyPayload(data) {
      currentReport = data.report;
      triageState = data.triage_state || {};
      currentAlerts = currentReport.alerts || [];
      updateKPIs();
      renderMitre();
      renderTable();
    }

    function updateKPIs() {
      if (!currentReport) return;
      const weights = { CRITICAL: 35, HIGH: 20, MEDIUM: 10, LOW: 5 };
      let openScore = 0;
      let openCount = 0;
      let resolvedCount = 0;

      currentAlerts.forEach(a => {
        const st = (triageState[alertKey(a)] || {}).status || 'OPEN';
        if (st === 'RESOLVED') {
          resolvedCount++;
        } else {
          openCount++;
          openScore += weights[a.severity] || 5;
        }
      });

      openScore = Math.min(100, openScore);
      const level = openScore >= 75 ? 'CRITICAL' : openScore >= 45 ? 'HIGH' : openScore >= 20 ? 'MODERATE' : 'LOW';

      document.getElementById('kpi-posture').textContent = `${level} (${openScore}/100)`;
      document.getElementById('kpi-sub').textContent = `Recalculated live from ${openCount} open alerts`;
      document.getElementById('kpi-events').textContent = currentReport.total_events;
      document.getElementById('kpi-alerts').textContent = `${openCount} / ${resolvedCount}`;
      document.getElementById('kpi-topip').textContent = currentReport.top_source_ips.length
        ? `${currentReport.top_source_ips[0].ip} (${currentReport.top_source_ips[0].alerts})`
        : 'None';
    }

    function renderMitre() {
      const tactics = ['Initial Access', 'Credential Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Reconnaissance'];
      const active = currentAlerts.map(a => a.mitre_tactic);
      document.getElementById('mitre-grid').innerHTML = tactics.map(t => {
        const hit = active.some(x => x.includes(t));
        return hit
          ? `<span class="px-2.5 py-1 rounded-lg bg-red-500/15 border border-red-500/40 text-red-300 font-semibold">${t} • HIT</span>`
          : `<span class="px-2.5 py-1 rounded-lg bg-[#060911] border border-gray-800 text-gray-500">${t}</span>`;
      }).join('');
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
        tbody.innerHTML = '<tr><td colspan="5" class="p-8 text-center text-gray-500">No alerts match current filter.</td></tr>';
        return;
      }

      const sevBadge = {
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
        const key = alertKey(a);
        const stObj = triageState[key] || { status: 'OPEN', notes: '' };
        return `<tr onclick='openDrawer(${JSON.stringify(a).replace(/'/g, "&#39;")})' class="hover:bg-white/[0.03] cursor-pointer transition">
          <td class="p-3.5"><span class="px-2 py-0.5 rounded border text-[10px] font-bold ${sevBadge[a.severity] || ''}">${a.severity}</span></td>
          <td class="p-3.5">
            <div class="font-semibold text-white">${a.rule_id}: ${a.title}</div>
            <div class="text-gray-400 mt-0.5">${a.evidence}</div>
            ${stObj.notes ? `<div class="text-indigo-300 text-[11px] mt-1">Note: ${stObj.notes}</div>` : ''}
          </td>
          <td class="p-3.5 mono text-purple-300">${a.mitre_technique}</td>
          <td class="p-3.5 mono text-gray-300">${a.host}<br><span class="text-cyan-400">${a.source_ip}</span></td>
          <td class="p-3.5"><span class="px-2.5 py-1 rounded border text-[10px] mono ${stBadge[stObj.status]}">${stObj.status}</span></td>
        </tr>`;
      }).join('');
    }

    async function openDrawer(a) {
      activeAlertKey = alertKey(a);
      const stObj = triageState[activeAlertKey] || { status: 'OPEN', notes: '' };

      document.getElementById('dr-badge').textContent = `${a.severity} • ${a.rule_id}`;
      document.getElementById('dr-badge').className = 'px-2 py-0.5 rounded text-[10px] font-bold mono bg-indigo-500/20 text-indigo-300';
      document.getElementById('dr-title').textContent = a.title;
      document.getElementById('dr-mitre').textContent = `${a.mitre_tactic} | ${a.mitre_technique}`;
      document.getElementById('dr-evidence').textContent = `${a.evidence} (Host: ${a.host}, User: ${a.user}, Time: ${a.timestamp})`;
      document.getElementById('dr-remediation').textContent = a.remediation;
      document.getElementById('dr-status').value = stObj.status;
      document.getElementById('dr-notes').value = stObj.notes || '';
      document.getElementById('dr-block-btn').onclick = () => {
        const cmd = `sudo ufw deny from ${a.source_ip} to any`;
        navigator.clipboard.writeText(cmd);
        showToast('Copied block rule: ' + cmd);
      };

      const drawer = document.getElementById('drawer');
      drawer.classList.remove('hidden');
      drawer.classList.add('flex');

      // Real IP & Reverse DNS Enrichment call
      document.getElementById('dr-enrich').innerHTML = 'Running Reverse DNS & IP classification...';
      const res = await fetch('/api/enrich?ip=' + encodeURIComponent(a.source_ip));
      const info = await res.json();
      document.getElementById('dr-enrich').innerHTML = `
        <div>IP Address: <span class="text-white">${info.ip}</span></div>
        <div>Scope:      <span class="text-amber-300">${info.scope}</span></div>
        <div>rDNS (PTR): <span class="text-emerald-300">${info.rdns}</span></div>
      `;
    }

    function closeDrawer() {
      const drawer = document.getElementById('drawer');
      drawer.classList.add('hidden');
      drawer.classList.remove('flex');
    }

    async function saveTriage() {
      const status = document.getElementById('dr-status').value;
      const notes = document.getElementById('dr-notes').value;
      const res = await fetch('/api/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: activeAlertKey, status, notes })
      });
      const data = await res.json();
      triageState = data.triage_state;
      closeDrawer();
      updateKPIs();
      renderTable();
      showToast(`Saved: ${status} (Persisted to incidents_state.json)`);
    }

    function exportReport(fmt) {
      if (!currentReport) { showToast('Run an analysis first!'); return; }
      window.open('/api/export?fmt=' + fmt, '_blank');
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
                self._send_json({"report": asdict(report), "triage_state": load_triage_state()})
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
        elif parsed.path == "/api/enrich":
            ip = params.get("ip", [""])[0]
            self._send_json(enrich_ip(ip))
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
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        if self.path == "/api/analyze":
            try:
                data = json.loads(body)
                threshold = int(data.get("threshold", 4))
                events = parse_raw_text(data.get("raw", ""))
                alerts = detect_threats(events, brute_force_threshold=threshold)
                report = build_report(events, alerts, "web-console-input")
                export_json(report, BASE_DIR / "output" / "report.json")
                export_html(report, BASE_DIR / "output" / "report.html")
                self._send_json({"report": asdict(report), "triage_state": load_triage_state()})
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
        elif self.path == "/api/triage":
            try:
                data = json.loads(body)
                state = load_triage_state()
                state[data["key"]] = {"status": data["status"], "notes": data.get("notes", "")}
                save_triage_state(state)
                self._send_json({"triage_state": state})
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
