"""
Signal Collector
=================
Runs as a background thread.
Every 5 seconds it measures all network signals and stores the latest
snapshot in a thread-safe object that the root cause engine reads.

Signals collected:
  - RTT to a target IP          (via ping subprocess)
  - Jitter                      (std-dev of 5 RTT samples)
  - RTT baseline                (EWMA of historical RTT — for path change detection)
  - TCP retransmissions rate    (delta of netstat -s per interval)
  - DNS response time           (timed socket.getaddrinfo call)
  - Wi-Fi signal strength       (netsh wlan show interfaces)
  - CPU usage                   (psutil.cpu_percent)
  - Top bandwidth PID           (from classifier shared state)

No Npcap or Administrator rights required.
"""

import re
import socket
import subprocess
import threading
import time
import math
import psutil
from dataclasses import dataclass, field
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
#  SIGNAL SNAPSHOT  — one object holds the latest reading of every signal
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class SignalSnapshot:
    # RTT signals
    rtt_ms:           float  = -1.0    # latest RTT to target (ms), -1 = unreachable
    jitter_ms:        float  = -1.0    # std-dev of last 5 RTT samples
    rtt_baseline_ms:  float  = -1.0    # EWMA of historical RTT (the "normal")
    rtt_jump:         bool   = False   # True if rtt_ms > 3× rtt_baseline_ms
    rtt_sustained_high: bool = False   # True if rtt has been elevated for > 30 s

    # Packet loss signals
    retransmit_rate:  float  = 0.0     # retransmissions per second (delta)
    retransmit_high:  bool   = False   # True if rate > threshold

    # DNS signal
    dns_ms:           float  = -1.0    # time to resolve a test domain (ms)
    dns_slow:         bool   = False   # True if dns_ms > 2000 ms

    # Wi-Fi signal
    wifi_signal_pct:  int    = -1      # 0-100, -1 = ethernet or unavailable
    wifi_weak:        bool   = False   # True if < 50%

    # Local resource signals
    cpu_pct:          float  = 0.0
    cpu_high:         bool   = False   # True if > 85%

    # Timestamp
    collected_at:     float  = field(default_factory=time.time)


# ══════════════════════════════════════════════════════════════════════════════
#  SIGNAL COLLECTOR CLASS
# ══════════════════════════════════════════════════════════════════════════════
class SignalCollector:
    """
    Usage:
        collector = SignalCollector(target_ip="8.8.8.8")
        collector.start()
        ...
        snap = collector.snapshot   # always the latest reading
    """

    # Thresholds
    RTT_HIGH_MULTIPLIER  = 3.0    # rtt > 3× baseline → path change suspected
    RTT_SUSTAINED_SECS   = 30     # how long RTT must be high to call it sustained
    RETRANSMIT_THRESHOLD = 5.0    # retransmissions/sec above this → packet loss
    DNS_SLOW_MS          = 2000   # DNS response above this → DNS problem
    WIFI_WEAK_THRESHOLD  = 50     # Wi-Fi signal below this % → weak signal
    CPU_HIGH_THRESHOLD   = 85     # CPU above this % → local contention
    EWMA_ALPHA           = 0.1    # baseline smoothing for RTT

    COLLECT_INTERVAL     = 5      # seconds between full signal collection

    def __init__(self, target_ip: str = "8.8.8.8", dns_test_host: str = "google.com"):
        self.target_ip      = target_ip
        self.dns_test_host  = dns_test_host

        self._lock          = threading.Lock()
        self._snapshot      = SignalSnapshot()

        # Internal state for running calculations
        self._rtt_baseline  = -1.0        # EWMA RTT baseline
        self._rtt_history   = []          # recent RTT readings for jitter
        self._rtt_high_secs = 0           # consecutive seconds RTT has been high
        self._last_retrans  = -1          # last raw retransmission count

    def start(self):
        """Start the background collection thread."""
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    @property
    def snapshot(self) -> SignalSnapshot:
        with self._lock:
            return self._snapshot

    def update_target_ip(self, ip: str):
        """Call this when the degraded PID's remote IP is known."""
        self.target_ip = ip

    # ── Internal loop ─────────────────────────────────────────────────────────
    def _loop(self):
        while True:
            snap = SignalSnapshot()

            # Run all collectors
            snap.rtt_ms, snap.jitter_ms = self._measure_rtt_jitter()
            snap.rtt_baseline_ms        = self._update_rtt_baseline(snap.rtt_ms)
            snap.rtt_jump               = self._check_rtt_jump(snap.rtt_ms, snap.rtt_baseline_ms)
            snap.rtt_sustained_high     = self._check_rtt_sustained(snap.rtt_jump)
            snap.retransmit_rate        = self._measure_retransmissions()
            snap.retransmit_high        = snap.retransmit_rate > self.RETRANSMIT_THRESHOLD
            snap.dns_ms                 = self._measure_dns()
            snap.dns_slow               = snap.dns_ms > self.DNS_SLOW_MS if snap.dns_ms >= 0 else False
            snap.wifi_signal_pct        = self._measure_wifi()
            snap.wifi_weak              = (0 <= snap.wifi_signal_pct < self.WIFI_WEAK_THRESHOLD)
            snap.cpu_pct                = psutil.cpu_percent(interval=None)
            snap.cpu_high               = snap.cpu_pct > self.CPU_HIGH_THRESHOLD
            snap.collected_at           = time.time()

            with self._lock:
                self._snapshot = snap

            time.sleep(self.COLLECT_INTERVAL)

    # ── RTT + Jitter via ping ─────────────────────────────────────────────────
    def _measure_rtt_jitter(self) -> tuple:
        """
        Ping the target IP 5 times and return (avg_rtt_ms, jitter_ms).
        Returns (-1, -1) if unreachable.
        Uses Windows 'ping -n 5' command via subprocess.
        """
        try:
            result = subprocess.run(
                ["ping", "-n", "5", "-w", "1000", self.target_ip],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout

            # Parse individual RTT values from lines like "Reply from x: bytes=32 time=14ms TTL=55"
            times = re.findall(r"time[=<](\d+)ms", output)
            if not times:
                return -1.0, -1.0

            rtts = [float(t) for t in times]
            avg  = sum(rtts) / len(rtts)

            # Jitter = standard deviation of RTT samples
            if len(rtts) > 1:
                variance = sum((r - avg) ** 2 for r in rtts) / len(rtts)
                jitter   = math.sqrt(variance)
            else:
                jitter = 0.0

            # Keep rolling history for sustained checks
            self._rtt_history.append(avg)
            if len(self._rtt_history) > 12:   # keep last 60s worth (12 × 5s)
                self._rtt_history.pop(0)

            return round(avg, 1), round(jitter, 1)

        except Exception:
            return -1.0, -1.0

    # ── RTT baseline EWMA ─────────────────────────────────────────────────────
    def _update_rtt_baseline(self, rtt_ms: float) -> float:
        """
        Maintain a slow-moving EWMA baseline of RTT.
        Only update when RTT is not currently elevated — same freeze logic
        as the degradation engine's EWMA.
        """
        if rtt_ms < 0:
            return self._rtt_baseline

        if self._rtt_baseline < 0:
            # First valid reading — initialise baseline
            self._rtt_baseline = rtt_ms
            return self._rtt_baseline

        # Only update if RTT is not dramatically above baseline
        # (prevents a bad route from becoming the new normal)
        if rtt_ms < self._rtt_baseline * self.RTT_HIGH_MULTIPLIER:
            self._rtt_baseline = (
                self.EWMA_ALPHA * rtt_ms
                + (1 - self.EWMA_ALPHA) * self._rtt_baseline
            )

        return round(self._rtt_baseline, 1)

    # ── RTT jump detection ────────────────────────────────────────────────────
    def _check_rtt_jump(self, rtt_ms: float, baseline_ms: float) -> bool:
        """True if current RTT is more than 3× the baseline."""
        if rtt_ms < 0 or baseline_ms <= 0:
            return False
        return rtt_ms > baseline_ms * self.RTT_HIGH_MULTIPLIER

    # ── RTT sustained elevation ───────────────────────────────────────────────
    def _check_rtt_sustained(self, rtt_jump: bool) -> bool:
        """
        True if RTT has been elevated for >= RTT_SUSTAINED_SECS continuously.
        Counter increments by COLLECT_INTERVAL each cycle.
        """
        if rtt_jump:
            self._rtt_high_secs += self.COLLECT_INTERVAL
        else:
            self._rtt_high_secs = 0
        return self._rtt_high_secs >= self.RTT_SUSTAINED_SECS

    # ── TCP retransmissions via netstat ───────────────────────────────────────
    def _measure_retransmissions(self) -> float:
        """
        Returns retransmissions per second since last call.
        Parses 'netstat -s -p tcp' on Windows.
        Falls back to psutil errin/errout if netstat fails.
        """
        try:
            result = subprocess.run(
                ["netstat", "-s", "-p", "tcp"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout

            # Look for "Segments Retransmitted" in netstat output
            match = re.search(r"(\d+)\s+segments retransmitted", output, re.IGNORECASE)
            if not match:
                # Try alternate format
                match = re.search(r"Segments Retransmitted\s*=\s*(\d+)", output, re.IGNORECASE)

            if match:
                current = int(match.group(1))
                if self._last_retrans < 0:
                    self._last_retrans = current
                    return 0.0
                delta = max(0, current - self._last_retrans)
                self._last_retrans = current
                return round(delta / self.COLLECT_INTERVAL, 2)   # per second

        except Exception:
            pass

        # Fallback: psutil network error counters
        try:
            counters = psutil.net_io_counters()
            errs = counters.errin + counters.errout
            if self._last_retrans < 0:
                self._last_retrans = errs
                return 0.0
            delta = max(0, errs - self._last_retrans)
            self._last_retrans = errs
            return round(delta / self.COLLECT_INTERVAL, 2)
        except Exception:
            return 0.0

    # ── DNS response time ─────────────────────────────────────────────────────
    def _measure_dns(self) -> float:
        """
        Time a DNS resolution of dns_test_host.
        Returns milliseconds, or -1 on failure.
        """
        try:
            start = time.perf_counter()
            socket.getaddrinfo(self.dns_test_host, 80)
            elapsed = (time.perf_counter() - start) * 1000
            return round(elapsed, 1)
        except Exception:
            return -1.0

    # ── Wi-Fi signal strength ─────────────────────────────────────────────────
    def _measure_wifi(self) -> int:
        """
        Returns Wi-Fi signal strength as integer 0-100.
        Returns -1 if on ethernet or Wi-Fi info unavailable.
        Parses 'netsh wlan show interfaces' on Windows.
        """
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout
            match = re.search(r"Signal\s*:\s*(\d+)%", output)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return -1