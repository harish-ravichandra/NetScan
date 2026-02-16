"""
NetScan - Web-based Network Port Scanner

A lightweight, open-source web interface for scanning network ranges for
open ports using Nmap. Supports configurable target networks, manual and
scheduled scanning, real-time results via SSE, and export functionality.
"""

import os
import io
import csv
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import timedelta, datetime, timezone
import subprocess
from threading import Lock, Thread
import atexit
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask, request, render_template_string, jsonify, Response, make_response
)
from apscheduler.schedulers.background import BackgroundScheduler

# =============================================================================
# Configuration
# =============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')
RESULTS_FILE = os.path.join(BASE_DIR, 'scan_results.json')

DEFAULT_CONFIG = {
    'networks': {},
    'ports': '--top-ports 1000',
    'timing_template': 4,
    'scan_interval_minutes': 30,
}

file_lock = Lock()
config_lock = Lock()


def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            saved = json.load(f)
            merged = {**DEFAULT_CONFIG, **saved}
            return merged
    except (FileNotFoundError, json.JSONDecodeError):
        return DEFAULT_CONFIG.copy()


def save_config(cfg):
    with config_lock:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(cfg, f, indent=2)


config = load_config()

# =============================================================================
# Logging
# =============================================================================
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
file_handler = RotatingFileHandler('netscan.log', maxBytes=500_000, backupCount=3)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)

logger = logging.getLogger('netscan')
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# =============================================================================
# Flask App
# =============================================================================
app = Flask(__name__)

# =============================================================================
# Scan State Management
# =============================================================================
live_scan_queue = Queue()
running_nmap_processes = []
process_lock = Lock()
scheduler = BackgroundScheduler(daemon=True)
LOCAL_TZ_OFFSET = datetime.now(timezone.utc).astimezone().utcoffset()


# =============================================================================
# Nmap Scanning Logic
# =============================================================================
def parse_nmap_output(nmap_output):
    """Parse Nmap grepable output for open ports."""
    open_ports = []
    for line in nmap_output.splitlines():
        if "Ports:" in line and "open" in line:
            parts = line.split()
            ip = parts[1]
            for token in parts:
                if "/open/" in token:
                    port = token.split('/')[0]
                    open_ports.append({'ip': ip, 'port': int(port)})
    return open_ports


def build_nmap_command(cidr):
    """Build the nmap command based on current config."""
    ports_setting = config.get('ports', '--top-ports 1000')
    timing = config.get('timing_template', 4)

    command = ["nmap", f"-T{timing}", "--open"]
    if ports_setting.startswith("--"):
        command.extend(ports_setting.split())
    else:
        command.extend(["-p", ports_setting])
    command.extend([cidr, "-oG", "-"])
    return command


def scan_single_network(name, cidr, stream=False):
    """Scan a single network using Nmap."""
    if stream:
        live_scan_queue.put({'type': 'status', 'network': name})

    logger.info(f"Scanning {name} ({cidr})")
    command = build_nmap_command(cidr)

    process = None
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        with process_lock:
            running_nmap_processes.append(process)

        stdout, stderr = process.communicate()

        with process_lock:
            if process in running_nmap_processes:
                running_nmap_processes.remove(process)

        if process.returncode != 0:
            logger.error(f"Nmap failed for {name}: {stderr}")
            if stream:
                live_scan_queue.put({'type': 'network_done', 'network': name})
            return name, []

        open_ports = parse_nmap_output(stdout)
        logger.info(f"{name}: found {len(open_ports)} open ports")

        if stream:
            for result in open_ports:
                live_scan_queue.put({'type': 'result', 'network': name, **result})
            live_scan_queue.put({'type': 'network_done', 'network': name})

        return name, open_ports

    except FileNotFoundError:
        logger.error("Nmap not found. Install nmap and ensure it's in PATH.")
        if stream:
            live_scan_queue.put({'type': 'error', 'message': 'Nmap not installed'})
            live_scan_queue.put({'type': 'network_done', 'network': name})
        return name, []
    except Exception as e:
        logger.error(f"Error scanning {name}: {e}", exc_info=True)
        with process_lock:
            if process and process in running_nmap_processes:
                running_nmap_processes.remove(process)
        if stream:
            live_scan_queue.put({'type': 'network_done', 'network': name})
        return name, []


def run_scan_task(stream=False):
    """Run scans for all configured networks in parallel."""
    networks = config.get('networks', {})
    if not networks:
        logger.info("No networks configured. Skipping scan.")
        if stream:
            live_scan_queue.put({'type': 'done'})
        return

    logger.info(f"Starting scan of {len(networks)} networks...")

    with ThreadPoolExecutor(max_workers=max(len(networks), 1)) as executor:
        futures = {
            executor.submit(scan_single_network, name, cidr, stream): name
            for name, cidr in networks.items()
        }
        for future in as_completed(futures):
            try:
                net_name, open_ports = future.result()
                # Always persist results
                with file_lock:
                    try:
                        with open(RESULTS_FILE, 'r') as f:
                            data = json.load(f)
                    except (FileNotFoundError, json.JSONDecodeError):
                        data = {'last_scan': None, 'results': {}}
                    if 'results' not in data:
                        data['results'] = {}
                    data['results'][net_name] = open_ports
                    with open(RESULTS_FILE, 'w') as f:
                        json.dump(data, f)
            except Exception as e:
                net_name = futures[future]
                logger.error(f"Scan task failed for {net_name}: {e}", exc_info=True)

    # Update timestamp
    now = datetime.now(timezone.utc).astimezone()
    with file_lock:
        try:
            with open(RESULTS_FILE, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {'last_scan': None, 'results': {}}
        data['last_scan'] = now.strftime("%Y-%m-%d %H:%M:%S")
        with open(RESULTS_FILE, 'w') as f:
            json.dump(data, f)

    if stream:
        live_scan_queue.put({'type': 'done'})

    logger.info("Scan complete.")


# =============================================================================
# HTML Template
# =============================================================================
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScan</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .mono { font-family: 'JetBrains Mono', monospace; }
    </style>
</head>
<body class="bg-slate-50 min-h-screen text-slate-700">
    <!-- Navbar -->
    <nav class="bg-white border-b border-slate-200 shadow-sm">
        <div class="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
            <div class="flex items-center space-x-3">
                <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/>
                </svg>
                <h1 class="text-xl font-bold text-slate-900">NetScan</h1>
                <span class="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full font-medium">Nmap</span>
            </div>
            <button onclick="openSettings()" class="text-slate-400 hover:text-slate-700 transition p-2 rounded-lg hover:bg-slate-100" title="Scan Settings">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                    <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                </svg>
            </button>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto px-6 py-8 space-y-6">
        <!-- Network Management -->
        <div class="bg-white rounded-xl border border-slate-200 shadow-sm">
            <div class="flex items-center justify-between px-6 py-4 border-b border-slate-100">
                <h2 class="text-sm font-semibold text-slate-900 uppercase tracking-wider">Target Networks</h2>
                <button onclick="openAddNetwork()" class="flex items-center space-x-1.5 text-sm font-medium text-blue-600 hover:text-blue-700 transition">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4"/></svg>
                    <span>Add Network</span>
                </button>
            </div>
            <div id="networks-list" class="divide-y divide-slate-100">
                <!-- populated by JS -->
            </div>
            <div id="no-networks" class="hidden px-6 py-8 text-center text-sm text-slate-400">
                No networks configured. Click "Add Network" to get started.
            </div>
        </div>

        <!-- Scan Controls -->
        <div class="flex flex-wrap items-center gap-3">
            <button id="manual-scan-btn" onclick="startManualScan()" class="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition disabled:bg-slate-300 disabled:cursor-not-allowed flex items-center space-x-2">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                <span>Scan Now</span>
            </button>
            <button onclick="startAutoScan()" class="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold rounded-lg transition flex items-center space-x-2">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <span>Auto-Scan</span>
            </button>
            <button onclick="stopAllScans()" class="px-5 py-2.5 bg-red-600 hover:bg-red-700 text-white font-semibold rounded-lg transition flex items-center space-x-2">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/><path stroke-linecap="round" stroke-linejoin="round" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z"/></svg>
                <span>Stop</span>
            </button>
            <button onclick="clearResults()" class="px-5 py-2.5 bg-slate-200 hover:bg-slate-300 text-slate-700 font-medium rounded-lg transition">Clear Results</button>

            <div class="relative ml-auto">
                <button onclick="toggleExport()" class="px-5 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-600 font-medium rounded-lg transition border border-slate-200 flex items-center space-x-2">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                    <span>Export</span>
                </button>
                <div id="export-menu" class="hidden absolute right-0 mt-2 w-40 bg-white border border-slate-200 rounded-lg shadow-lg z-10 py-1">
                    <a href="/export/json" class="block px-4 py-2 text-sm text-slate-700 hover:bg-slate-50">Export as JSON</a>
                    <a href="/export/csv" class="block px-4 py-2 text-sm text-slate-700 hover:bg-slate-50">Export as CSV</a>
                </div>
            </div>
        </div>

        <!-- Status Bar -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div class="bg-white rounded-lg border border-slate-200 px-4 py-3">
                <p class="text-xs text-slate-400 uppercase tracking-wider mb-1">Last Scan</p>
                <p class="text-sm font-semibold text-slate-900" id="last-scan-time">N/A</p>
            </div>
            <div class="bg-white rounded-lg border border-slate-200 px-4 py-3">
                <p class="text-xs text-slate-400 uppercase tracking-wider mb-1">Next Scheduled</p>
                <p class="text-sm font-semibold text-slate-900" id="next-scan-time">N/A</p>
            </div>
            <div class="bg-white rounded-lg border border-slate-200 px-4 py-3">
                <p class="text-xs text-slate-400 uppercase tracking-wider mb-1">Status</p>
                <p class="text-sm font-semibold" id="scan-status-text">Idle</p>
            </div>
        </div>

        <!-- Results Grid -->
        <div id="results-container" class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6"></div>
    </main>

    <!-- Add Network Modal -->
    <div id="add-network-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/40 backdrop-blur-sm" onclick="closeAddNetwork()"></div>
        <div class="relative bg-white border border-slate-200 rounded-2xl shadow-2xl w-full max-w-md mx-4 p-6">
            <h3 class="text-lg font-bold text-slate-900 mb-4">Add Network</h3>
            <div class="space-y-4">
                <div>
                    <label class="block text-xs font-medium text-slate-500 mb-1.5 uppercase tracking-wider">Network Name</label>
                    <input type="text" id="net-name" placeholder="e.g., Office LAN"
                           class="w-full px-3 py-2.5 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500">
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-500 mb-1.5 uppercase tracking-wider">CIDR Range</label>
                    <input type="text" id="net-cidr" placeholder="e.g., 192.168.1.0/24"
                           class="w-full px-3 py-2.5 border border-slate-300 rounded-lg mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500">
                </div>
            </div>
            <div id="add-net-error" class="hidden mt-3 text-sm text-red-600"></div>
            <div class="flex space-x-3 mt-6">
                <button onclick="addNetwork()" class="flex-1 px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg transition">Add</button>
                <button onclick="closeAddNetwork()" class="flex-1 px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-lg transition">Cancel</button>
            </div>
        </div>
    </div>

    <!-- Settings Modal -->
    <div id="settings-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/40 backdrop-blur-sm" onclick="closeSettings()"></div>
        <div class="relative bg-white border border-slate-200 rounded-2xl shadow-2xl w-full max-w-md mx-4 p-6">
            <div class="flex items-center justify-between mb-6">
                <h3 class="text-lg font-bold text-slate-900">Scan Settings</h3>
                <button onclick="closeSettings()" class="text-slate-400 hover:text-slate-700">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
                </button>
            </div>
            <form id="settings-form">
                <div class="space-y-4">
                    <div>
                        <label class="block text-xs font-medium text-slate-500 mb-1.5 uppercase tracking-wider">Ports to Scan</label>
                        <input type="text" name="ports"
                               class="w-full px-3 py-2.5 border border-slate-300 rounded-lg mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                               placeholder="--top-ports 1000 or 22,80,443" id="setting-ports">
                        <p class="text-xs text-slate-400 mt-1">Use --top-ports N, a range like 1-1024, or a comma-separated list</p>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-slate-500 mb-1.5 uppercase tracking-wider">Timing Template (T0-T5)</label>
                        <select name="timing_template" id="setting-timing"
                                class="w-full px-3 py-2.5 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50">
                            <option value="0">T0 - Paranoid</option>
                            <option value="1">T1 - Sneaky</option>
                            <option value="2">T2 - Polite</option>
                            <option value="3">T3 - Normal</option>
                            <option value="4">T4 - Aggressive</option>
                            <option value="5">T5 - Insane</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-slate-500 mb-1.5 uppercase tracking-wider">Auto-Scan Interval (minutes)</label>
                        <input type="number" name="scan_interval_minutes" min="1" max="1440" id="setting-interval"
                               class="w-full px-3 py-2.5 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50">
                    </div>
                </div>
                <div class="flex space-x-3 mt-6">
                    <button type="button" onclick="saveSettings()" class="flex-1 px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg transition">Save</button>
                    <button type="button" onclick="closeSettings()" class="flex-1 px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium rounded-lg transition">Cancel</button>
                </div>
            </form>
            <div id="settings-msg" class="hidden mt-3 text-center text-sm text-emerald-600"></div>
        </div>
    </div>

    <script>
        let eventSource = null;
        let scanningNetworks = [];
        let statusInterval = null;
        let refreshInterval = null;

        // ===== Data Loading =====
        async function loadData(fullUpdate = true) {
            const res = await fetch('/scanner_data');
            const data = await res.json();

            document.getElementById('last-scan-time').textContent = data.last_scan || 'N/A';
            document.getElementById('next-scan-time').textContent = data.next_scan || 'N/A';

            renderNetworksList(data.networks || {});

            if (fullUpdate) {
                const container = document.getElementById('results-container');
                container.innerHTML = '';
                const networks = data.networks || {};
                for (const name in networks) {
                    createNetworkCard(name);
                    const tbody = document.getElementById(`results-${name}`);
                    const results = (data.results || {})[name];
                    if (results && results.length > 0) {
                        tbody.innerHTML = results.map(r => resultRow(r)).join('');
                    } else {
                        tbody.innerHTML = emptyRow('No open ports found.');
                    }
                }
            }
        }

        function renderNetworksList(networks) {
            const list = document.getElementById('networks-list');
            const empty = document.getElementById('no-networks');
            const entries = Object.entries(networks);

            if (entries.length === 0) {
                list.innerHTML = '';
                empty.classList.remove('hidden');
                return;
            }
            empty.classList.add('hidden');
            list.innerHTML = entries.map(([name, cidr]) => `
                <div class="flex items-center justify-between px-6 py-3">
                    <div class="flex items-center space-x-4">
                        <span class="w-2 h-2 rounded-full bg-blue-400"></span>
                        <span class="font-medium text-slate-900 text-sm">${name}</span>
                        <code class="mono text-xs text-slate-500 bg-slate-100 px-2 py-0.5 rounded">${cidr}</code>
                    </div>
                    <button onclick="removeNetwork('${name}')" class="text-slate-400 hover:text-red-500 transition p-1 rounded hover:bg-red-50" title="Remove">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                    </button>
                </div>
            `).join('');
        }

        function createNetworkCard(name) {
            const container = document.getElementById('results-container');
            if (document.getElementById(`card-${name}`)) return;
            container.innerHTML += `
                <div id="card-${name}" class="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
                    <div class="px-5 py-3 border-b border-slate-100 bg-slate-50">
                        <h3 class="font-semibold text-slate-900 text-sm">${name}</h3>
                    </div>
                    <div class="max-h-80 overflow-y-auto">
                        <table class="w-full">
                            <thead class="bg-slate-50/50 sticky top-0">
                                <tr>
                                    <th class="px-5 py-2 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">IP Address</th>
                                    <th class="px-5 py-2 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Port</th>
                                    <th class="px-5 py-2 text-center text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                                </tr>
                            </thead>
                            <tbody id="results-${name}" class="divide-y divide-slate-50">
                                ${emptyRow('Waiting for scan...')}
                            </tbody>
                        </table>
                    </div>
                </div>`;
        }

        function resultRow(r) {
            return `<tr>
                <td class="px-5 py-2.5 text-sm mono text-slate-700">${r.ip}</td>
                <td class="px-5 py-2.5 text-sm mono text-slate-500">${r.port}</td>
                <td class="px-5 py-2.5 text-center">
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-100 text-emerald-700">Open</span>
                </td>
            </tr>`;
        }

        function emptyRow(msg) {
            return `<tr><td colspan="3" class="px-5 py-4 text-center text-sm text-slate-400">${msg}</td></tr>`;
        }

        // ===== Network Management =====
        function openAddNetwork() {
            document.getElementById('add-network-modal').classList.remove('hidden');
            document.getElementById('net-name').value = '';
            document.getElementById('net-cidr').value = '';
            document.getElementById('add-net-error').classList.add('hidden');
            document.getElementById('net-name').focus();
        }
        function closeAddNetwork() {
            document.getElementById('add-network-modal').classList.add('hidden');
        }

        async function addNetwork() {
            const name = document.getElementById('net-name').value.trim();
            const cidr = document.getElementById('net-cidr').value.trim();
            const errEl = document.getElementById('add-net-error');
            if (!name || !cidr) {
                errEl.textContent = 'Both fields are required.';
                errEl.classList.remove('hidden');
                return;
            }
            const cidrRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
            if (!cidrRegex.test(cidr)) {
                errEl.textContent = 'Invalid CIDR format. Example: 192.168.1.0/24';
                errEl.classList.remove('hidden');
                return;
            }
            const res = await fetch('/networks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, cidr })
            });
            if (res.ok) {
                closeAddNetwork();
                loadData(true);
            } else {
                const data = await res.json();
                errEl.textContent = data.error || 'Failed to add network.';
                errEl.classList.remove('hidden');
            }
        }

        async function removeNetwork(name) {
            if (!confirm(`Remove "${name}" from targets?`)) return;
            await fetch(`/networks/${encodeURIComponent(name)}`, { method: 'DELETE' });
            loadData(true);
        }

        // ===== Scanning =====
        function setStatus(text, color = 'slate') {
            const el = document.getElementById('scan-status-text');
            el.textContent = text;
            el.className = `text-sm font-semibold text-${color}-600`;
        }

        function startManualScan() {
            const btn = document.getElementById('manual-scan-btn');
            btn.disabled = true;
            btn.querySelector('span').textContent = 'Scanning...';
            setStatus('Initializing scan...', 'blue');
            scanningNetworks = [];

            if (statusInterval) clearInterval(statusInterval);

            const container = document.getElementById('results-container');
            container.innerHTML = '';
            fetch('/scanner_data').then(r => r.json()).then(data => {
                for (const name in (data.networks || {})) {
                    createNetworkCard(name);
                }
            });

            eventSource = new EventSource('/stream_scan');

            eventSource.onmessage = function(event) {
                const data = JSON.parse(event.data);

                if (data.type === 'status') {
                    if (!scanningNetworks.includes(data.network)) scanningNetworks.push(data.network);
                    if (!statusInterval) {
                        let idx = 0;
                        statusInterval = setInterval(() => {
                            if (scanningNetworks.length > 0) {
                                setStatus(`Scanning ${scanningNetworks[idx % scanningNetworks.length]}...`, 'blue');
                                idx++;
                            } else {
                                clearInterval(statusInterval);
                                statusInterval = null;
                                setStatus('Scan complete.', 'emerald');
                                loadData(true);
                            }
                        }, 2000);
                    }
                }
                else if (data.type === 'result') {
                    const tbody = document.getElementById(`results-${data.network}`);
                    if (tbody && tbody.querySelector('td[colspan="3"]')) tbody.innerHTML = '';
                    if (tbody) tbody.innerHTML += resultRow(data);
                }
                else if (data.type === 'network_done') {
                    const i = scanningNetworks.indexOf(data.network);
                    if (i > -1) scanningNetworks.splice(i, 1);
                    const tbody = document.getElementById(`results-${data.network}`);
                    if (tbody && (!tbody.hasChildNodes() || tbody.querySelector('td[colspan="3"]'))) {
                        tbody.innerHTML = emptyRow('No open ports found.');
                    }
                }
            };

            eventSource.onerror = function() {
                setStatus(scanningNetworks.length === 0 ? 'Scan complete.' : 'Scan interrupted.', scanningNetworks.length === 0 ? 'emerald' : 'amber');
                btn.disabled = false;
                btn.querySelector('span').textContent = 'Scan Now';
                eventSource.close();
                if (statusInterval) clearInterval(statusInterval);
                statusInterval = null;
                scanningNetworks = [];
                setTimeout(() => loadData(true), 1000);
            };
        }

        async function startAutoScan() {
            setStatus('Starting auto-scan scheduler...', 'blue');
            await fetch('/start_auto_scan');
            setTimeout(() => { setStatus('Auto-scan active.', 'emerald'); loadData(true); }, 2000);
        }

        async function stopAllScans() {
            setStatus('Stopping...', 'red');
            await fetch('/stop_scans');
            if (eventSource) eventSource.close();
            if (statusInterval) clearInterval(statusInterval);
            statusInterval = null;
            scanningNetworks = [];
            const btn = document.getElementById('manual-scan-btn');
            btn.disabled = false;
            btn.querySelector('span').textContent = 'Scan Now';
            setTimeout(() => { setStatus('Idle', 'slate'); loadData(true); }, 1500);
        }

        async function clearResults() {
            await fetch('/clear_results');
            loadData(true);
            setStatus('Results cleared.', 'slate');
        }

        // ===== Export =====
        function toggleExport() {
            document.getElementById('export-menu').classList.toggle('hidden');
        }
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.relative')) {
                document.getElementById('export-menu').classList.add('hidden');
            }
        });

        // ===== Settings =====
        function openSettings() {
            fetch('/settings').then(r => r.json()).then(data => {
                document.getElementById('setting-ports').value = data.ports || '';
                document.getElementById('setting-timing').value = data.timing_template || 4;
                document.getElementById('setting-interval').value = data.scan_interval_minutes || 30;
                document.getElementById('settings-modal').classList.remove('hidden');
                document.getElementById('settings-msg').classList.add('hidden');
            });
        }
        function closeSettings() {
            document.getElementById('settings-modal').classList.add('hidden');
        }
        async function saveSettings() {
            const data = {
                ports: document.getElementById('setting-ports').value.trim(),
                timing_template: parseInt(document.getElementById('setting-timing').value),
                scan_interval_minutes: parseInt(document.getElementById('setting-interval').value),
            };
            const res = await fetch('/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const msg = document.getElementById('settings-msg');
            if (res.ok) {
                msg.textContent = 'Settings saved!';
                msg.classList.remove('hidden');
                setTimeout(closeSettings, 1500);
            } else {
                msg.textContent = 'Error saving settings.';
                msg.className = 'mt-3 text-center text-sm text-red-600';
                msg.classList.remove('hidden');
            }
        }

        // ===== Init =====
        document.addEventListener('DOMContentLoaded', () => {
            loadData(true);
            refreshInterval = setInterval(() => loadData(true), 30000);
        });
    </script>
</body>
</html>
"""


# =============================================================================
# Routes - Main
# =============================================================================
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/scanner_data')
def scanner_data():
    with file_lock:
        try:
            with open(RESULTS_FILE, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {'last_scan': None, 'results': {}}

    data['networks'] = config.get('networks', {})

    if scheduler.running:
        try:
            jobs = scheduler.get_jobs()
            if jobs and jobs[0].next_run_time:
                local_next = jobs[0].next_run_time.astimezone()
                data['next_scan'] = local_next.strftime("%Y-%m-%d %H:%M:%S")
            else:
                data['next_scan'] = "Scheduler active, no jobs."
        except Exception:
            data['next_scan'] = "Error"
    else:
        data['next_scan'] = "Not running"

    return jsonify(data)


# =============================================================================
# Routes - Network Management
# =============================================================================
@app.route('/networks', methods=['GET', 'POST'])
def networks():
    global config
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name', '').strip()
        cidr = data.get('cidr', '').strip()

        if not name or not cidr:
            return jsonify({'error': 'Name and CIDR are required.'}), 400

        if name in config.get('networks', {}):
            return jsonify({'error': f'Network "{name}" already exists.'}), 400

        if 'networks' not in config:
            config['networks'] = {}
        config['networks'][name] = cidr
        save_config(config)
        logger.info(f"Network added: {name} ({cidr})")
        return jsonify({'status': 'ok'})

    return jsonify(config.get('networks', {}))


@app.route('/networks/<name>', methods=['DELETE'])
def delete_network(name):
    global config
    networks = config.get('networks', {})
    if name in networks:
        del networks[name]
        config['networks'] = networks
        save_config(config)
        logger.info(f"Network removed: {name}")
        return jsonify({'status': 'ok'})
    return jsonify({'error': 'Not found'}), 404


# =============================================================================
# Routes - Scanning
# =============================================================================
@app.route('/stream_scan')
def stream_scan():
    def event_stream():
        thread = Thread(target=run_scan_task, kwargs={'stream': True})
        thread.start()
        while True:
            data = live_scan_queue.get()
            if data['type'] == 'done':
                break
            yield f"data: {json.dumps(data)}\n\n"
    return Response(event_stream(), mimetype='text/event-stream')


@app.route('/stop_scans')
def stop_scans():
    global scheduler
    logger.info("Stopping all scans")
    with process_lock:
        for p in running_nmap_processes:
            try:
                p.terminate()
            except ProcessLookupError:
                pass
        running_nmap_processes.clear()

    if scheduler.running:
        scheduler.shutdown()
        scheduler = BackgroundScheduler(daemon=True)
        logger.info("Scheduler stopped")

    return jsonify({'status': 'ok'})


@app.route('/start_auto_scan')
def start_auto_scan():
    global config
    interval = config.get('scan_interval_minutes', 30)
    logger.info(f"Starting auto-scan (interval: {interval}m)")

    if not scheduler.running:
        try:
            scheduler.add_job(
                run_scan_task, 'interval',
                minutes=interval,
                id='scan_job',
                kwargs={'stream': False},
                replace_existing=True
            )
            scheduler.start()
            scheduler.get_job('scan_job').modify(next_run_time=datetime.now(timezone.utc))
            return jsonify({'status': 'ok'})
        except Exception as e:
            logger.error(f"Scheduler error: {e}")
            return jsonify({'error': str(e)}), 500
    return jsonify({'status': 'already_running'})


@app.route('/clear_results')
def clear_results():
    logger.info("Clearing results")
    with file_lock:
        data = {'last_scan': None, 'results': {n: [] for n in config.get('networks', {})}}
        with open(RESULTS_FILE, 'w') as f:
            json.dump(data, f)
    return jsonify({'status': 'ok'})


# =============================================================================
# Routes - Export
# =============================================================================
@app.route('/export/json')
def export_json():
    with file_lock:
        try:
            with open(RESULTS_FILE, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {'last_scan': None, 'results': {}}

    response = make_response(json.dumps(data, indent=2))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename=netscan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    return response


@app.route('/export/csv')
def export_csv():
    with file_lock:
        try:
            with open(RESULTS_FILE, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {'last_scan': None, 'results': {}}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Network', 'IP Address', 'Port', 'Status', 'Scan Time'])

    for network, results in data.get('results', {}).items():
        for entry in results:
            writer.writerow([network, entry['ip'], entry['port'], 'open', data.get('last_scan', '')])

    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=netscan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    return response


# =============================================================================
# Routes - Settings
# =============================================================================
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    global config
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data'}), 400

        if 'ports' in data:
            config['ports'] = data['ports']
        if 'timing_template' in data:
            config['timing_template'] = int(data['timing_template'])
        if 'scan_interval_minutes' in data:
            config['scan_interval_minutes'] = int(data['scan_interval_minutes'])

        save_config(config)
        logger.info(f"Settings updated: ports={config['ports']}, timing=T{config['timing_template']}, interval={config['scan_interval_minutes']}m")
        return jsonify({'status': 'ok'})

    return jsonify({
        'ports': config.get('ports', '--top-ports 1000'),
        'timing_template': config.get('timing_template', 4),
        'scan_interval_minutes': config.get('scan_interval_minutes', 30),
    })


# =============================================================================
# Initialization
# =============================================================================
def initialize():
    with file_lock:
        if not os.path.exists(RESULTS_FILE):
            data = {'last_scan': None, 'results': {n: [] for n in config.get('networks', {})}}
            with open(RESULTS_FILE, 'w') as f:
                json.dump(data, f)
    atexit.register(lambda: scheduler.shutdown() if scheduler.running else None)
    logger.info("NetScan initialized")


if __name__ == '__main__':
    initialize()
    host = os.environ.get('NETSCAN_HOST', '0.0.0.0')
    port = int(os.environ.get('NETSCAN_PORT', '5000'))
    logger.info(f"Starting NetScan on {host}:{port}")
    app.run(debug=True, host=host, port=port)
