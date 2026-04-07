"""
Behavioral App-Class Classifier  +  Degradation Engine  +  Root Cause Engine
==============================================================================
Stage 1 — classify what each app is doing
Stage 2 — detect when it degrades
Stage 3 — explain why it degraded

Files produced:
  classifier_log.csv       — every active flow every 2s
  degradation_alerts.csv   — confirmed degradation events
  root_cause_log.csv       — root cause analysis for each alert

Run:
    python behavioral_classifier.py
"""

import psutil
import socket
import threading
import time
import csv
import os
from collections import defaultdict, deque
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box

from degradation_engine import DegradationEngine, Alert
from signal_collector import SignalCollector
from root_cause_engine import RootCauseEngine, RootCause

try:
    from database import db_write_classifier_row, db_write_alert, db_write_rootcause
    _DB_AVAILABLE = True
except ImportError:
    _DB_AVAILABLE = False

console = Console()

REFRESH_INTERVAL = 2          # seconds between detection cycles
MIN_KBPS_DISPLAY = 1
MAX_ROWS_DISPLAY = 20

PROCESS_CLASS = {
    'msedge.exe':         'Browser',
    'chrome.exe':         'Browser',
    'firefox.exe':        'Browser',
    'brave.exe':          'Browser',
    'opera.exe':          'Browser',
    'vgc.exe':            'Gaming',
    'valorant.exe':       'Gaming',
    'steam.exe':          'Gaming/Download',
    'steamwebhelper.exe': 'Gaming',
    'csgo.exe':           'Gaming',
    'r5apex.exe':         'Gaming',
    'spotify.exe':        'Audio Streaming',
    'discord.exe':        'VoIP/Chat',
    'zoom.exe':           'Video Conference',
    'teams.exe':          'Video Conference',
    'qbittorrent.exe':    'P2P Download',
    'IDMan.exe':          'Download Manager',
}

HOSTNAME_RULES = [
    ('googlevideo.com',        'Video Streaming (YouTube)'),
    ('ytimg.com',              'Video Streaming (YouTube)'),
    ('youtube.com',            'Video Streaming (YouTube)'),
    ('nflxvideo.net',          'Video Streaming (Netflix)'),
    ('nflximg.net',            'Video Streaming (Netflix)'),
    ('hotstar.com',            'Video Streaming (Hotstar)'),
    ('primevideo.com',         'Video Streaming (Prime)'),
    ('twitch.tv',              'Video Streaming (Twitch)'),
    ('akamaized.net',          'Video/CDN'),
    ('cloudfront.net',         'Video/Download (CDN)'),
    ('scdn.co',                'Audio Streaming (Spotify)'),
    ('spotify.com',            'Audio Streaming (Spotify)'),
    ('discord.com',            'VoIP/Chat (Discord)'),
    ('zoom.us',                'Video Conference (Zoom)'),
    ('teams.microsoft.com',    'Video Conference (Teams)'),
    ('dl.google.com',          'Software Download'),
    ('download.microsoft.com', 'Software Download'),
    ('github.com',             'Dev/Download (GitHub)'),
    ('githubusercontent.com',  'Dev/Download (GitHub)'),
    ('epicgames.com',          'Gaming/Download (Epic)'),
    ('steampowered.com',       'Gaming/Download (Steam)'),
    ('google.com',             'Web Browsing (Google)'),
    ('bing.com',               'Web Browsing (Bing)'),
    ('microsoft.com',          'Web (Microsoft)'),
    ('live.com',               'Web/Email (Microsoft)'),
    ('office.com',             'Cloud Office'),
    ('amazonaws.com',          'Cloud/Download (AWS)'),
]

# ── Shared state ──────────────────────────────────────────────────────────────
lock              = threading.Lock()
pid_to_name       = {}
pid_io_history    = defaultdict(lambda: deque(maxlen=10))
pid_last_io       = {}
ip_hostname_cache = {}
pid_remote_ips    = defaultdict(set)
display_rows      = []
recent_alerts     = deque(maxlen=5)
recent_rootcauses = deque(maxlen=5)

engine    = DegradationEngine()
rce       = RootCauseEngine()
collector = SignalCollector(target_ip="8.8.8.8")

# ── Classifier CSV ────────────────────────────────────────────────────────────
CSV_LOG_FILE = "classifier_log.csv"
CSV_HEADERS  = ["timestamp", "pid", "process", "current_kbps",
                "avg_kbps", "classification", "severity", "resolved_host"]

def init_csv():
    if not os.path.isfile(CSV_LOG_FILE):
        with open(CSV_LOG_FILE, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=CSV_HEADERS).writeheader()

def write_csv(rows: list):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(CSV_LOG_FILE, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        for r in rows:
            w.writerow({
                "timestamp":      ts,
                "pid":            r["pid"],
                "process":        r["proc"],
                "current_kbps":   f"{r['kbps']:.1f}",
                "avg_kbps":       f"{r['avg_kbps']:.1f}",
                "classification": r["classification"],
                "severity":       r["severity"],
                "resolved_host":  r.get("hostname", ""),
            })
        f.flush()

# ── Thread 1: psutil I/O polling ──────────────────────────────────────────────
def poll_process_io():
    global pid_to_name, pid_remote_ips
    while True:
        new_names   = {}
        new_remotes = defaultdict(set)
        try:
            conns = psutil.net_connections(kind='inet')
        except Exception:
            conns = []

        for conn in conns:
            if conn.pid and conn.raddr:
                new_remotes[conn.pid].add(conn.raddr.ip)

        for pid, ips in new_remotes.items():
            try:
                proc    = psutil.Process(pid)
                name    = proc.name().lower()
                new_names[pid] = name
                try:
                    io      = proc.io_counters()
                    current = io.read_bytes + io.write_bytes
                except (psutil.AccessDenied, AttributeError):
                    current = 0
                with lock:
                    delta = max(0, current - pid_last_io.get(pid, current))
                    pid_last_io[pid] = current
                    pid_io_history[pid].append(delta)
                    pid_remote_ips[pid] = ips
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        with lock:
            pid_to_name = new_names
        time.sleep(1)

# ── Thread 2: DNS reverse lookup ──────────────────────────────────────────────
def dns_resolver():
    resolved = set()
    while True:
        with lock:
            all_ips = {ip for ips in pid_remote_ips.values() for ip in ips}
        for ip in all_ips - resolved:
            if ':' in ip:
                resolved.add(ip)
                continue
            try:
                hostname = socket.gethostbyaddr(ip)[0].lower()
            except Exception:
                hostname = ip
            with lock:
                ip_hostname_cache[ip] = hostname
            resolved.add(ip)
        time.sleep(2)

# ── Classification helpers ────────────────────────────────────────────────────
def best_label_for_pid(pid: int):
    with lock:
        ips   = set(pid_remote_ips.get(pid, set()))
        cache = dict(ip_hostname_cache)
    for ip in ips:
        h = cache.get(ip, '')
        for domain, label in HOSTNAME_RULES:
            if domain in h:
                return label, h
    return None, None

def bytes_to_kbps(b: int) -> float:
    return (b * 8) / 1000

def classify(pid: int, proc: str, history: list):
    total        = sum(history)
    n            = len(history)
    avg_bps      = total / n if n else 0
    avg_kbps     = bytes_to_kbps(int(avg_bps))
    max_bps      = max(history) if history else 0
    active_ratio = sum(1 for b in history if b > 0) / n if n else 0
    burstiness   = (max_bps / avg_bps) if avg_bps > 0 else 1

    label, hostname = best_label_for_pid(pid)
    short_host = ""
    if hostname:
        parts      = hostname.split('.')
        short_host = '.'.join(parts[-3:]) if len(parts) >= 3 else hostname

    if label:
        return label, short_host
    broad = PROCESS_CLASS.get(proc)
    if broad and broad != 'Browser':
        return broad, short_host
    if total == 0:
        return "Idle / Background", short_host
    if avg_kbps < 20:
        return "Web Browsing (Low traffic)", short_host
    if avg_kbps > 6000:
        return "Large File Download", short_host
    if burstiness > 2.5 and avg_kbps > 300 and active_ratio < 0.7:
        return "Video Streaming (Bursty)", short_host
    if avg_kbps > 1500 and active_ratio > 0.8:
        return "Download / Rich Streaming", short_host
    if avg_kbps > 200:
        return "Active Web / Media", short_host
    return "Light Web Browsing", short_host

# ── Thread 3: snapshot + detection + CSV write ────────────────────────────────
def snapshot_and_detect():
    global display_rows
    while True:
        time.sleep(REFRESH_INTERVAL)

        with lock:
            names     = dict(pid_to_name)
            histories = {pid: list(pid_io_history[pid]) for pid in names}

        rows        = []
        active_pids = set()

        for pid, proc in names.items():
            hist = histories.get(pid, [])
            if not hist or sum(hist) == 0:
                continue

            label, hostname = classify(pid, proc, hist)

            # instant kbps from last 1-second slice
            instant_kbps = bytes_to_kbps(hist[-1])
            # smoothed average over rolling window — used for detection
            avg_kbps     = bytes_to_kbps(sum(hist) / len(hist))

            if avg_kbps < MIN_KBPS_DISPLAY:
                continue

            active_pids.add(pid)

            # Feed BOTH instant and average into engine
            # Engine uses avg for detection, instant for display only
            alert: Alert = engine.update(pid, proc, label, instant_kbps, avg_kbps)

            if alert:
                # Update signal collector to ping this PID's remote IP
                with lock:
                    remote_ips = list(pid_remote_ips.get(pid, set()))
                ipv4s = [ip for ip in remote_ips if ':' not in ip]
                if ipv4s:
                    collector.update_target_ip(ipv4s[0])

                snap       = collector.snapshot
                root_cause = rce.analyse(alert, snap)

                # Persist alert & root cause to SQL DB
                if _DB_AVAILABLE:
                    try:
                        db_write_alert(alert)
                        db_write_rootcause(root_cause)
                    except Exception:
                        pass

                with lock:
                    recent_alerts.appendleft(alert)
                    recent_rootcauses.appendleft(root_cause)

            state    = engine.get_state(pid)
            severity = state.severity if state else 0

            rows.append({
                "pid":            pid,
                "proc":           proc,
                "kbps":           instant_kbps,
                "avg_kbps":       avg_kbps,
                "classification": label,
                "severity":       severity,
                "hostname":       hostname,
            })

        # Clean up gone PIDs
        for pid in list(engine.all_states().keys()):
            if pid not in active_pids:
                engine.remove_pid(pid)

        rows.sort(key=lambda r: r["avg_kbps"], reverse=True)

        with lock:
            display_rows = rows[:MAX_ROWS_DISPLAY]

        if rows:
            write_csv(rows)
            # Also persist to SQL database
            if _DB_AVAILABLE:
                for r in rows:
                    try:
                        db_write_classifier_row(r)
                    except Exception:
                        pass

# ── Display helpers ───────────────────────────────────────────────────────────
def severity_style(score: int):
    if score == 0:  return "dim",      "OK"
    if score < 30:  return "green",    f"{score}"
    if score < 60:  return "yellow",   f"{score}"
    if score < 80:  return "bold red", f"{score}!"
    return "bold red", f"{score}!!"

def label_colour(label: str) -> str:
    l = label.lower()
    if 'youtube' in l or 'video streaming' in l: return "red"
    if 'audio'   in l or 'spotify' in l:         return "green"
    if 'gaming'  in l:                           return "magenta"
    if 'download' in l:                          return "cyan"
    if 'voip'    in l or 'conference' in l:      return "yellow"
    return "bright_white"

def speed_colour(kbps: float) -> str:
    if kbps > 5000: return "bold red"
    if kbps > 1000: return "bold yellow"
    if kbps > 200:  return "green"
    return "white"

def cause_colour(cause: str) -> str:
    c = cause.lower()
    if 'wi-fi'    in c: return "yellow"
    if 'isp'      in c: return "bold red"
    if 'bufferbloat' in c: return "red"
    if 'route'    in c: return "magenta"
    if 'dns'      in c: return "cyan"
    if 'throttl'  in c: return "blue"
    if 'local'    in c: return "yellow"
    return "white"

# ── Build rich table ──────────────────────────────────────────────────────────
def build_table() -> Table:
    now  = datetime.now().strftime("%H:%M:%S")
    snap = collector.snapshot

    rtt_str  = f"RTT {snap.rtt_ms:.0f}ms"       if snap.rtt_ms >= 0          else "RTT --"
    jit_str  = f"jitter {snap.jitter_ms:.0f}ms"  if snap.jitter_ms >= 0       else ""
    wifi_str = f"Wi-Fi {snap.wifi_signal_pct}%"  if snap.wifi_signal_pct >= 0 else "ethernet"
    dns_str  = f"DNS {snap.dns_ms:.0f}ms"        if snap.dns_ms >= 0          else ""
    cpu_str  = f"CPU {snap.cpu_pct:.0f}%"
    signals  = "  |  ".join(filter(None, [rtt_str, jit_str, wifi_str, dns_str, cpu_str]))

    table = Table(
        title=(
            f"[bold cyan]Real-Time Network Monitor[/]  [dim]{now}[/]\n"
            f"[dim]{signals}[/]"
        ),
        box=box.ROUNDED, show_lines=True, expand=True,
        header_style="bold white on dark_blue",
    )
    table.add_column("PID",            style="dim",        width=7,  justify="right")
    table.add_column("Process",        style="bold",       width=16)
    table.add_column("Instant",        justify="right",    width=12)
    table.add_column("Avg (10s)",      justify="right",    width=12)
    table.add_column("Sev",            justify="center",   width=6)
    table.add_column("Classification",                     min_width=24)
    table.add_column("Host",           style="dim italic", min_width=18)

    with lock:
        rows       = list(display_rows)
        rootcauses = list(recent_rootcauses)

    if not rows:
        table.add_row("—","—","—","—","—","[dim]No active flows — open a browser or start a download[/]","")
        return table

    for r in rows:
        sev_style, sev_label = severity_style(r["severity"])
        table.add_row(
            str(r["pid"]),
            r["proc"],
            Text(f"{r['kbps']:>7.0f} kbps",     style=speed_colour(r["kbps"])),
            Text(f"{r['avg_kbps']:>7.0f} kbps",  style=speed_colour(r["avg_kbps"])),
            Text(sev_label,                       style=sev_style),
            Text(r["classification"],             style=label_colour(r["classification"])),
            r.get("hostname", ""),
        )

    if rootcauses:
        table.add_section()
        for rc in rootcauses[:3]:
            table.add_row(
                "", f"[bold red]ALERT[/]",
                f"[red]{rc.alert.current_kbps:.0f} kbps[/]",
                f"[dim]sev {rc.alert.severity}[/]",
                f"[bold]{rc.confidence}%[/]",
                Text(f"{rc.cause}  —  {rc.recommendation}", style=cause_colour(rc.cause)),
                rc.timestamp,
            )
            evidence_str = "  |  ".join(rc.evidence[:2])
            table.add_row("","","","","",f"[dim]{evidence_str}[/]","")

    return table

# ── Main ──────────────────────────────────────────────────────────────────────
def run():
    init_csv()
    console.print(f"\n[bold cyan]Network Monitor — Stage 1 + 2 + 3[/]")
    console.print(f"[dim]Classifier log : {os.path.abspath(CSV_LOG_FILE)}[/]")
    console.print(f"[dim]Alerts log     : {os.path.abspath(engine.ALERT_CSV)}[/]")
    console.print(f"[dim]Root cause log : {os.path.abspath(rce.CAUSE_CSV)}[/]\n")
    console.print("[yellow]Warming up — 5 seconds...[/]\n")

    threading.Thread(target=poll_process_io,    daemon=True).start()
    threading.Thread(target=dns_resolver,        daemon=True).start()
    threading.Thread(target=snapshot_and_detect, daemon=True).start()
    collector.start()

    time.sleep(5)

    with Live(
        build_table(), console=console,
        refresh_per_second=1, vertical_overflow="visible"
    ) as live:
        try:
            while True:
                time.sleep(1)
                live.update(build_table())
        except KeyboardInterrupt:
            pass

    console.print(f"\n[bold green]Stopped.[/]")

if __name__ == "__main__":
    run()