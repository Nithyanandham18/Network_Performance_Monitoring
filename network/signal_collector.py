import re
import socket
import subprocess
import threading
import time
import math
import psutil
from dataclasses import dataclass, field

@dataclass
class SignalSnapshot:
    rtt_ms:           float  = -1.0 
    jitter_ms:        float  = -1.0 
    rtt_baseline_ms:  float  = -1.0 
    rtt_jump:         bool   = False 
    rtt_sustained_high: bool = False 
    retransmit_rate:  float  = 0.0   
    retransmit_high:  bool   = False 
    dns_ms:           float  = -1.0  
    dns_slow:         bool   = False 
    wifi_signal_pct:  int    = -1    
    wifi_weak:        bool   = False 
    cpu_pct:          float  = 0.0
    cpu_high:         bool   = False 
    collected_at:     float  = field(default_factory=time.time)

class SignalCollector:
    RTT_HIGH_MULTIPLIER  = 3.0
    RTT_SUSTAINED_SECS   = 30
    RETRANSMIT_THRESHOLD = 0.5   # lowered from 5.0 — 2/s is realistic under packet loss
    DNS_SLOW_MS          = 2000
    WIFI_WEAK_THRESHOLD  = 50
    CPU_HIGH_THRESHOLD   = 85
    EWMA_ALPHA           = 0.1
    COLLECT_INTERVAL     = 2     # match REFRESH_INTERVAL so snapshot is never stale

    def __init__(self, target_ip: str = "8.8.8.8", dns_test_host: str = "google.com"):
        self.target_ip      = target_ip
        self.dns_test_host  = dns_test_host
        self._lock          = threading.Lock()
        self._snapshot      = SignalSnapshot()
        self._rtt_baseline  = -1.0
        self._rtt_history   = []
        self._rtt_high_secs = 0
        self._rtt_normal_streak = 0   # consecutive normal readings before reset
        self._last_retrans  = -1          

    def start(self):
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    @property
    def snapshot(self) -> SignalSnapshot:
        with self._lock:
            return self._snapshot

    def update_target_ip(self, ip: str):
        self.target_ip = ip

    def _loop(self):
        while True:
            snap = SignalSnapshot()
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

    def _measure_rtt_jitter(self) -> tuple:
        try:
            result = subprocess.run(["ping", "-n", "5", "-w", "1000", self.target_ip], capture_output=True, text=True, timeout=10)
            times = re.findall(r"time[=<](\d+)ms", result.stdout)
            if not times: return -1.0, -1.0
            rtts = [float(t) for t in times]
            avg  = sum(rtts) / len(rtts)
            jitter = math.sqrt(sum((r - avg) ** 2 for r in rtts) / len(rtts)) if len(rtts) > 1 else 0.0
            return round(avg, 1), round(jitter, 1)
        except Exception:
            return -1.0, -1.0

    def _update_rtt_baseline(self, rtt_ms: float) -> float:
        if rtt_ms < 0: return self._rtt_baseline
        if self._rtt_baseline < 0:
            self._rtt_baseline = rtt_ms
            return self._rtt_baseline
        if rtt_ms < self._rtt_baseline * self.RTT_HIGH_MULTIPLIER:
            self._rtt_baseline = (self.EWMA_ALPHA * rtt_ms + (1 - self.EWMA_ALPHA) * self._rtt_baseline)
        return round(self._rtt_baseline, 1)

    def _check_rtt_jump(self, rtt_ms: float, baseline_ms: float) -> bool:
        if rtt_ms < 0 or baseline_ms <= 0: return False
        return rtt_ms > baseline_ms * self.RTT_HIGH_MULTIPLIER

    def _check_rtt_sustained(self, rtt_jump: bool) -> bool:
        if rtt_jump:
            self._rtt_high_secs += self.COLLECT_INTERVAL
            self._rtt_normal_streak = 0
        else:
            self._rtt_normal_streak += 1
            # Only reset after 2 consecutive normal readings
            # This prevents a single good ping from clearing a route change
            if self._rtt_normal_streak >= 2:
                self._rtt_high_secs = 0
        return self._rtt_high_secs >= self.RTT_SUSTAINED_SECS

    def _measure_retransmissions(self) -> float:
        try:
            result = subprocess.run(["netstat", "-s", "-p", "tcp"], capture_output=True, text=True, timeout=5)
            match = re.search(r"(\d+)\s+segments retransmitted", result.stdout, re.IGNORECASE)
            if not match: match = re.search(r"Segments Retransmitted\s*=\s*(\d+)", result.stdout, re.IGNORECASE)
            if match:
                current = int(match.group(1))
                if self._last_retrans < 0:
                    self._last_retrans = current
                    return 0.0
                delta = max(0, current - self._last_retrans)
                self._last_retrans = current
                return round(delta / self.COLLECT_INTERVAL, 2)
        except Exception: pass
        return 0.0

    def _measure_dns(self) -> float:
        try:
            start = time.perf_counter()
            socket.getaddrinfo(self.dns_test_host, 80)
            return round((time.perf_counter() - start) * 1000, 1)
        except Exception:
            # If DNS is completely blocked (e.g. port 53 dropped), getaddrinfo
            # raises an exception after the OS timeout — treat as maximum slowness
            return 9999.0

    def _measure_wifi(self) -> int:
        try:
            result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=5)
            match = re.search(r"Signal\s*:\s*(\d+)%", result.stdout)
            if match: return int(match.group(1))
        except Exception: pass
        return -1