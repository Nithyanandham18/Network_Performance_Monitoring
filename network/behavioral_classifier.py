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

console = Console()

REFRESH_INTERVAL = 1 # Instant 1-second refresh rate
MIN_KBPS_DISPLAY = 1
MAX_ROWS_DISPLAY = 20

PROCESS_CLASS = {
    'msedge.exe':         'Browser',
    'chrome.exe':         'Browser',
    'firefox.exe':        'Browser',
    'brave.exe':          'Browser',
    'vgc.exe':            'Gaming',
    'valorant.exe':       'Gaming',
    'steam.exe':          'Gaming/Download',
    'csgo.exe':           'Gaming',
    'spotify.exe':        'Audio Streaming',
    'discord.exe':        'VoIP/Chat',
    'zoom.exe':           'Video Conference',
    'teams.exe':          'Video Conference',
    'qbittorrent.exe':    'P2P Download',
    'IDMan.exe':          'Download Manager',
}

HOSTNAME_RULES = [
    ('googlevideo.com',        'Video Streaming (YouTube)'),
    ('nflxvideo.net',          'Video Streaming (Netflix)'),
    ('twitch.tv',              'Video Streaming (Twitch)'),
    ('scdn.co',                'Audio Streaming (Spotify)'),
    ('discord.com',            'VoIP/Chat (Discord)'),
    ('github.com',             'Dev/Download (GitHub)'),
    ('steampowered.com',       'Gaming/Download (Steam)'),
]

lock              = threading.Lock()
pid_to_name       = {}
pid_io_history    = defaultdict(lambda: deque(maxlen=10))
pid_last_io       = {}
ip_hostname_cache = {}
pid_remote_ips    = defaultdict(set)
display_rows      = []
recent_rootcauses = deque(maxlen=5)

engine    = DegradationEngine()
rce       = RootCauseEngine()
collector = SignalCollector(target_ip="8.8.8.8")

def poll_process_io():
    global pid_to_name, pid_remote_ips
    while True:
        new_names   = {}
        new_remotes = defaultdict(set)
        try: conns = psutil.net_connections(kind='inet')
        except Exception: conns = []
        for conn in conns:
            if conn.pid and conn.raddr:
                new_remotes[conn.pid].add(conn.raddr.ip)
        for pid, ips in new_remotes.items():
            try:
                proc = psutil.Process(pid)
                name = proc.name().lower()
                new_names[pid] = name
                try:
                    io      = proc.io_counters()
                    current = io.read_bytes + io.write_bytes
                except (psutil.AccessDenied, AttributeError):
                    current = 0
                with lock:
                    delta = max(0, current - pid_last_io.get(pid, current))
                    pid_last_io[pid]  = current
                    pid_io_history[pid].append(delta)
                    pid_remote_ips[pid] = ips
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        with lock: pid_to_name = new_names
        time.sleep(1)

def dns_resolver():
    resolved = set()
    while True:
        with lock: all_ips = {ip for ips in pid_remote_ips.values() for ip in ips}
        for ip in all_ips - resolved:
            if ':' in ip:
                resolved.add(ip)
                continue
            try: hostname = socket.gethostbyaddr(ip)[0].lower()
            except Exception: hostname = ip
            with lock: ip_hostname_cache[ip] = hostname
            resolved.add(ip)
        time.sleep(2)

def best_label_for_pid(pid: int):
    with lock:
        ips   = set(pid_remote_ips.get(pid, set()))
        cache = dict(ip_hostname_cache)
    for ip in ips:
        h = cache.get(ip, '')
        for domain, label in HOSTNAME_RULES:
            if domain in h: return label, h
    return None, None

def bytes_to_kbps(b: int) -> float:
    return (b * 8) / 1000

def classify(pid: int, proc: str, history: list):
    total        = sum(history)
    avg_bps      = total / len(history) if history else 0
    avg_kbps     = bytes_to_kbps(int(avg_bps))
    max_bps      = max(history) if history else 0
    active_ratio = sum(1 for b in history if b > 0) / len(history) if history else 0
    burstiness   = (max_bps / avg_bps) if avg_bps > 0 else 1

    label, hostname = best_label_for_pid(pid)
    short_host = ""
    if hostname:
        parts = hostname.split('.')
        short_host = '.'.join(parts[-3:]) if len(parts) >= 3 else hostname

    if label: return label, short_host
    broad = PROCESS_CLASS.get(proc)
    if broad and broad != 'Browser': return broad, short_host
    if total == 0: return "Idle / Background", short_host
    if avg_kbps < 20: return "Web Browsing (Low traffic)", short_host
    if avg_kbps > 6000: return "Large File Download", short_host
    if burstiness > 2.5 and avg_kbps > 300 and active_ratio < 0.7: return "Video Streaming (Bursty)", short_host
    if avg_kbps > 1500 and active_ratio > 0.8: return "Download / Rich Streaming", short_host
    if avg_kbps > 200: return "Active Web / Media", short_host
    return "Light Web Browsing", short_host

def snapshot_and_detect():
    global display_rows
    while True:
        time.sleep(REFRESH_INTERVAL)
        with lock:
            names     = dict(pid_to_name)
            histories = {pid: list(pid_io_history[pid]) for pid in names}

        rows       = []
        active_pids = set()

        for pid, proc in names.items():
            hist = histories.get(pid, [])
            if not hist or sum(hist) == 0: continue

            label, hostname = classify(pid, proc, hist)
            kbps     = bytes_to_kbps(hist[-1])
            avg_kbps = bytes_to_kbps(sum(hist) / len(hist)) if hist else 0

            if kbps < MIN_KBPS_DISPLAY: continue
            active_pids.add(pid)

            # Check degradation
            alert = engine.update(pid, proc, label, kbps)

            if alert:
                with lock:
                    remote_ips = list(pid_remote_ips.get(pid, set()))
                ipv4s = [ip for ip in remote_ips if ':' not in ip]
                if ipv4s: collector.update_target_ip(ipv4s[0])

                snap       = collector.snapshot
                root_cause = rce.analyse(alert, snap)

                with lock:
                    recent_rootcauses.appendleft(root_cause)

            state    = engine.get_state(pid)
            severity = state.severity if state else 0

            rows.append({
                "pid":            pid,
                "proc":           proc,
                "kbps":           kbps,
                "avg_kbps":       avg_kbps,
                "classification": label,
                "severity":       severity,
                "hostname":       hostname,
            })

        for pid in list(engine.all_states().keys()):
            if pid not in active_pids: engine.remove_pid(pid)

        rows.sort(key=lambda r: r["kbps"], reverse=True)
        with lock: display_rows = rows[:MAX_ROWS_DISPLAY]

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
    return "bright_white"

def speed_colour(kbps: float) -> str:
    if kbps > 5000: return "bold red"
    if kbps > 1000: return "bold yellow"
    if kbps > 200:  return "green"
    return "white"

def cause_colour(cause: str) -> str:
    if 'wi-fi' in cause.lower(): return "yellow"
    if 'isp' in cause.lower(): return "bold red"
    return "white"

def build_table() -> Table:
    now  = datetime.now().strftime("%H:%M:%S")
    snap = collector.snapshot
    rtt_str  = f"RTT {snap.rtt_ms:.0f}ms" if snap.rtt_ms >= 0 else "RTT --"
    wifi_str = f"Wi-Fi {snap.wifi_signal_pct}%" if snap.wifi_signal_pct >= 0 else "ethernet"
    cpu_str  = f"CPU {snap.cpu_pct:.0f}%"
    signals  = "  |  ".join(filter(None, [rtt_str, wifi_str, cpu_str]))

    table = Table(
        title=f"[bold cyan]Real-Time Network Monitor[/]  [dim]{now}[/]\n[dim]{signals}[/]",
        box=box.ROUNDED, show_lines=True, expand=True, header_style="bold white on dark_blue",
    )

    table.add_column("PID",     style="dim", width=7, justify="right")
    table.add_column("Process", style="bold", width=16)
    table.add_column("Speed",   justify="right", width=12)
    table.add_column("Avg",     justify="right", width=12)
    table.add_column("Sev",     justify="center", width=6)
    table.add_column("Classification", min_width=24)
    table.add_column("Host",    style="dim italic", min_width=18)

    with lock:
        rows       = list(display_rows)
        rootcauses = list(recent_rootcauses)

    if not rows:
        table.add_row("—","—","—","—","—","[dim]No active flows[/]","")
        return table

    for r in rows:
        sev_style, sev_label = severity_style(r["severity"])
        table.add_row(
            str(r["pid"]), r["proc"],
            Text(f"{r['kbps']:>7.0f} kbps", style=speed_colour(r["kbps"])),
            Text(f"{r['avg_kbps']:>7.0f} kbps", style=speed_colour(r["avg_kbps"])),
            Text(sev_label, style=sev_style),
            Text(r["classification"], style=label_colour(r["classification"])),
            r.get("hostname", ""),
        )

    if rootcauses:
        table.add_section()
        for rc in rootcauses[:3]:
            table.add_row(
                "", f"[bold red]ALERT[/]", f"[red]{rc.alert.current_kbps:.0f} kbps[/]",
                f"[dim]sev {rc.alert.severity}[/]", f"[bold]{rc.confidence}%[/]",
                Text(f"{rc.cause}  —  {rc.recommendation}", style=cause_colour(rc.cause)),
                rc.timestamp,
            )
    return table

def run():
    console.print("[yellow]Initializing Real-Time Dashboard...[/]\n")
    threading.Thread(target=poll_process_io, daemon=True).start()
    threading.Thread(target=dns_resolver, daemon=True).start()
    threading.Thread(target=snapshot_and_detect, daemon=True).start()
    collector.start()
    time.sleep(3)

    with Live(build_table(), console=console, refresh_per_second=1, vertical_overflow="visible") as live:
        try:
            while True:
                time.sleep(1)
                live.update(build_table())
        except KeyboardInterrupt: pass

if __name__ == "__main__":
    run()