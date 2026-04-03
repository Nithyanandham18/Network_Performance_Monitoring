"""
Root Cause Engine
==================
Reads a SignalSnapshot and a confirmed Alert, then runs a
per-app-class decision tree to identify the probable root cause.

Each app-class has its own prioritised signal checklist:
  Gaming          → jitter/RTT first, then loss
  Video Streaming → throughput trend first, then loss
  File Download   → ISP throttling first (process of elimination)
  VoIP/Conference → jitter + upstream loss first
  Audio Streaming → connection drop + DNS first
  Default/Web     → generic decision tree

Simplified path change detection (no traceroute):
  RTT sudden jump  → suspect route change
  RTT sustained    → confirm route change

Output: RootCause object with cause, confidence %, evidence list,
        recommendation string.
"""

import csv
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from signal_collector import SignalSnapshot
from degradation_engine import Alert


# ══════════════════════════════════════════════════════════════════════════════
#  ROOT CAUSE RESULT
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class RootCause:
    # The alert that triggered this analysis
    alert:          Alert

    # Primary cause label
    cause:          str        # e.g. "Wi-Fi interference"
    confidence:     int        # 0-100 — how certain we are
    evidence:       list       # list of strings explaining what we observed
    recommendation: str        # one-line fix suggestion

    # Secondary cause (if signals point to two things)
    secondary_cause: Optional[str] = None

    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# Cause labels (constants so nothing is misspelled across the codebase)
CAUSE_WIFI_INTERFERENCE  = "Wi-Fi interference"
CAUSE_ISP_PACKET_LOSS    = "ISP / upstream packet loss"
CAUSE_BUFFERBLOAT        = "Bufferbloat / network congestion"
CAUSE_ROUTE_CHANGE       = "Network route change"
CAUSE_DNS_PROBLEM        = "DNS slowness or failure"
CAUSE_SERVER_THROTTLE    = "Server-side throttling"
CAUSE_LOCAL_CONTENTION   = "Local resource contention"
CAUSE_CONNECTION_DROP    = "Intermittent connection drop"
CAUSE_UNKNOWN            = "Unknown — insufficient signal data"


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _signals_available(snap: SignalSnapshot) -> bool:
    """Return True if we have at least RTT and retransmit data."""
    return snap.rtt_ms >= 0 or snap.retransmit_rate >= 0


def _network_looks_healthy(snap: SignalSnapshot) -> bool:
    """
    True when all network signals appear normal.
    Used as the last check before concluding server throttling.
    """
    return (
        not snap.rtt_jump
        and not snap.rtt_sustained_high
        and not snap.retransmit_high
        and not snap.dns_slow
        and not snap.wifi_weak
        and snap.rtt_ms < 150     # absolute RTT still reasonable
    )


def _packet_loss_cause(snap: SignalSnapshot) -> tuple:
    """
    Given that retransmissions are high, decide if it's Wi-Fi or ISP.
    Returns (cause, confidence, evidence).
    """
    evidence = [f"TCP retransmissions: {snap.retransmit_rate:.1f}/s (threshold 5/s)"]

    if snap.wifi_signal_pct >= 0:
        # On Wi-Fi — check signal
        evidence.append(f"Wi-Fi signal: {snap.wifi_signal_pct}%")
        if snap.wifi_weak:
            evidence.append("Weak Wi-Fi signal is causing wireless packet drops")
            return CAUSE_WIFI_INTERFERENCE, 85, evidence
        else:
            evidence.append("Wi-Fi signal is adequate — loss is beyond the router")
            return CAUSE_ISP_PACKET_LOSS, 78, evidence
    else:
        # On ethernet — loss must be upstream
        evidence.append("Ethernet connection — packet loss is beyond your router")
        return CAUSE_ISP_PACKET_LOSS, 80, evidence


# ══════════════════════════════════════════════════════════════════════════════
#  PER-APP-CLASS DECISION TREES
# ══════════════════════════════════════════════════════════════════════════════

def _diagnose_gaming(snap: SignalSnapshot, alert: Alert) -> tuple:
    """
    Gaming is real-time UDP. Tiny packets, low bandwidth.
    Priority: jitter → RTT → packet loss → server → local
    Even small jitter (>20ms) ruins the experience.
    """
    evidence = []

    # 1. Jitter is the primary enemy for gaming
    if snap.jitter_ms > 20:
        evidence.append(f"High jitter: {snap.jitter_ms:.1f}ms (>20ms hurts gaming)")
        if snap.retransmit_high:
            evidence.append(f"Also seeing retransmissions: {snap.retransmit_rate:.1f}/s")
            cause, conf, pkt_ev = _packet_loss_cause(snap)
            evidence += pkt_ev
            return cause, conf, evidence, "Reduce Wi-Fi interference or contact ISP about packet loss"

        if snap.rtt_jump or snap.rtt_sustained_high:
            evidence.append(f"RTT elevated: {snap.rtt_ms:.0f}ms (baseline: {snap.rtt_baseline_ms:.0f}ms)")
            if snap.rtt_sustained_high:
                evidence.append("RTT has been elevated for over 30s — route change likely")
                return CAUSE_ROUTE_CHANGE, 72, evidence, "Run tracert to game server to confirm route change"
            return CAUSE_BUFFERBLOAT, 75, evidence, "Enable QoS on your router, prioritise gaming traffic"

        # Jitter alone, no loss, no RTT issue
        if snap.wifi_signal_pct >= 0:
            evidence.append(f"Wi-Fi signal: {snap.wifi_signal_pct}%")
            if snap.wifi_weak:
                return CAUSE_WIFI_INTERFERENCE, 80, evidence, "Move closer to router or use ethernet"
            return CAUSE_BUFFERBLOAT, 68, evidence, "Enable QoS / reduce other traffic during gaming"

        return CAUSE_BUFFERBLOAT, 65, evidence, "Check router QoS settings"

    # 2. Packet loss without jitter
    if snap.retransmit_high:
        cause, conf, pkt_ev = _packet_loss_cause(snap)
        return cause, conf, pkt_ev, "Use ethernet, or contact ISP about packet loss"

    # 3. High RTT, no loss, no jitter
    if snap.rtt_jump:
        evidence.append(f"RTT jumped to {snap.rtt_ms:.0f}ms (baseline {snap.rtt_baseline_ms:.0f}ms)")
        if snap.rtt_sustained_high:
            evidence.append("Sustained for >30s — route likely changed")
            return CAUSE_ROUTE_CHANGE, 70, evidence, "Wait for route to recover or restart router"
        return CAUSE_BUFFERBLOAT, 62, evidence, "Reduce other network activity"

    # 4. CPU contention
    if snap.cpu_high:
        evidence.append(f"CPU at {snap.cpu_pct:.0f}% — local processing bottleneck")
        return CAUSE_LOCAL_CONTENTION, 74, evidence, "Close background applications"

    # 5. All clear — server side
    if _network_looks_healthy(snap):
        evidence.append(f"RTT normal ({snap.rtt_ms:.0f}ms), no packet loss, no jitter")
        evidence.append("All local signals healthy — issue likely on game server side")
        return CAUSE_SERVER_THROTTLE, 55, evidence, "Check game server status page"

    return CAUSE_UNKNOWN, 30, ["Insufficient signal data"], "Run test_engine.py to verify detection"


def _diagnose_video_streaming(snap: SignalSnapshot, alert: Alert) -> tuple:
    """
    Video streaming (YouTube, Netflix). Buffers ahead so tolerates brief spikes.
    Priority: sustained throughput drop → packet loss → DNS → bufferbloat → server
    Jitter matters less — RTT consistency matters less — sustained throughput is everything.
    """
    evidence = []

    # 1. Packet loss directly starves the buffer
    if snap.retransmit_high:
        cause, conf, pkt_ev = _packet_loss_cause(snap)
        evidence = pkt_ev + [f"Packet loss is draining the video buffer (severity {alert.severity})"]
        return cause, conf, evidence, "Switch to ethernet or move closer to router"

    # 2. DNS slow means new CDN segments can't connect
    if snap.dns_slow:
        evidence.append(f"DNS resolution taking {snap.dns_ms:.0f}ms (>2000ms)")
        evidence.append("Video CDN uses many short-lived connections — slow DNS blocks each one")
        return CAUSE_DNS_PROBLEM, 82, evidence, "Switch DNS to 8.8.8.8 or 1.1.1.1 in network settings"

    # 3. Route change — sustained RTT elevation
    if snap.rtt_sustained_high:
        evidence.append(f"RTT elevated for >30s: {snap.rtt_ms:.0f}ms vs baseline {snap.rtt_baseline_ms:.0f}ms")
        evidence.append("CDN node may have changed or a backbone route degraded")
        return CAUSE_ROUTE_CHANGE, 68, evidence, "Wait for CDN rerouting to stabilise (usually resolves in minutes)"

    # 4. Bufferbloat — RTT high but no packet loss
    if snap.rtt_jump:
        evidence.append(f"RTT jumped to {snap.rtt_ms:.0f}ms (baseline {snap.rtt_baseline_ms:.0f}ms)")
        evidence.append("High RTT slows TCP window — video segments arrive too slowly to buffer")
        return CAUSE_BUFFERBLOAT, 70, evidence, "Reduce concurrent downloads or enable router QoS"

    # 5. Local bandwidth contention
    if snap.cpu_high:
        evidence.append(f"CPU at {snap.cpu_pct:.0f}%")
        return CAUSE_LOCAL_CONTENTION, 65, evidence, "Close other applications consuming CPU"

    # 6. All network metrics normal → server throttling
    if _network_looks_healthy(snap):
        evidence.append(f"RTT: {snap.rtt_ms:.0f}ms, no packet loss, DNS fast")
        evidence.append(f"Network healthy — speed dropped {100 - int(alert.current_kbps/max(alert.baseline_kbps,1)*100)}% below baseline")
        evidence.append("CDN or ISP may be throttling this stream")
        return CAUSE_SERVER_THROTTLE, 60, evidence, "Try a VPN or different network to confirm throttling"

    return CAUSE_UNKNOWN, 30, ["Insufficient signal data"], "Check network connection manually"


def _diagnose_download(snap: SignalSnapshot, alert: Alert) -> tuple:
    """
    File downloads. Only cares about sustained throughput. High latency is irrelevant.
    Priority: ISP throttling (most common for large downloads) → packet loss → DNS → server
    Note: downloads tolerate latency well — RTT checks are less important here.
    """
    evidence = []

    # 1. Packet loss hurts downloads significantly (TCP slows on every loss)
    if snap.retransmit_high:
        cause, conf, pkt_ev = _packet_loss_cause(snap)
        evidence = pkt_ev + ["Packet loss is causing TCP to reduce its window size"]
        return cause, conf, evidence, "Use ethernet for large downloads"

    # 2. DNS slow (affects download managers that open many connections)
    if snap.dns_slow:
        evidence.append(f"DNS slow: {snap.dns_ms:.0f}ms")
        return CAUSE_DNS_PROBLEM, 70, evidence, "Switch DNS to 1.1.1.1"

    # 3. Route change — sustained RTT
    if snap.rtt_sustained_high:
        evidence.append(f"RTT sustained high: {snap.rtt_ms:.0f}ms vs {snap.rtt_baseline_ms:.0f}ms baseline")
        return CAUSE_ROUTE_CHANGE, 60, evidence, "Try pausing and resuming the download"

    # 4. All clear — for downloads, ISP throttling is the first suspect
    # ISPs commonly throttle large sustained TCP flows
    if _network_looks_healthy(snap):
        drop_pct = int((1 - alert.current_kbps / max(alert.baseline_kbps, 1)) * 100)
        evidence.append(f"Speed dropped {drop_pct}% below baseline")
        evidence.append("No packet loss, normal RTT, DNS healthy")
        evidence.append("ISPs commonly throttle large sustained downloads")
        return CAUSE_SERVER_THROTTLE, 65, evidence, "Try download at off-peak hours or use a VPN"

    return CAUSE_UNKNOWN, 30, ["Insufficient signal data"], "Check download source server status"


def _diagnose_voip(snap: SignalSnapshot, alert: Alert) -> tuple:
    """
    VoIP and video calls (Zoom, Teams, Discord). Real-time bidirectional.
    Priority: jitter → packet loss → RTT → local CPU → server
    Both directions matter. Jitter and loss cause broken audio/video.
    """
    evidence = []

    # 1. Jitter ruins call quality immediately
    if snap.jitter_ms > 15:
        evidence.append(f"Jitter: {snap.jitter_ms:.1f}ms (>15ms causes choppy audio/video)")
        if snap.wifi_weak:
            evidence.append(f"Weak Wi-Fi ({snap.wifi_signal_pct}%) is causing timing instability")
            return CAUSE_WIFI_INTERFERENCE, 82, evidence, "Use ethernet for video calls"
        if snap.retransmit_high:
            cause, conf, pkt_ev = _packet_loss_cause(snap)
            return cause, conf, evidence + pkt_ev, "Switch to ethernet or reduce Wi-Fi interference"
        return CAUSE_BUFFERBLOAT, 72, evidence, "Close other applications during the call"

    # 2. Packet loss — even 1% is very noticeable in real-time audio
    if snap.retransmit_high:
        cause, conf, pkt_ev = _packet_loss_cause(snap)
        pkt_ev.append("Even small packet loss causes gaps in real-time audio/video")
        return cause, conf, pkt_ev, "Use ethernet, or move closer to router"

    # 3. High RTT (>150ms causes noticeable call delay)
    if snap.rtt_ms > 150:
        evidence.append(f"RTT: {snap.rtt_ms:.0f}ms — above 150ms causes perceptible call delay")
        if snap.rtt_sustained_high:
            evidence.append("Sustained for >30s — likely a route change")
            return CAUSE_ROUTE_CHANGE, 68, evidence, "Restart router or wait for route to recover"
        return CAUSE_BUFFERBLOAT, 65, evidence, "Reduce other network activity during the call"

    # 4. CPU high — call encoding is CPU-intensive
    if snap.cpu_high:
        evidence.append(f"CPU at {snap.cpu_pct:.0f}% — call encoding/decoding is CPU-intensive")
        return CAUSE_LOCAL_CONTENTION, 78, evidence, "Close other applications during the call"

    if _network_looks_healthy(snap):
        evidence.append("All local signals healthy — issue may be on the call server side")
        return CAUSE_SERVER_THROTTLE, 50, evidence, "Check Zoom/Teams server status"

    return CAUSE_UNKNOWN, 30, ["Insufficient signal data"], "Check call quality settings"


def _diagnose_audio_streaming(snap: SignalSnapshot, alert: Alert) -> tuple:
    """
    Audio streaming (Spotify). Very low bandwidth — almost never a throughput problem.
    Priority: connection drop → DNS → server → local
    If audio is degraded, it's almost always a connection issue, not bandwidth.
    """
    evidence = []

    # 1. DNS — Spotify reconnects frequently, DNS failures block reconnection
    if snap.dns_slow:
        evidence.append(f"DNS slow: {snap.dns_ms:.0f}ms")
        evidence.append("Spotify reconnects often — slow DNS blocks each reconnection attempt")
        return CAUSE_DNS_PROBLEM, 80, evidence, "Switch DNS to 1.1.1.1 in network settings"

    # 2. Packet loss — small but meaningful for audio
    if snap.retransmit_high:
        cause, conf, pkt_ev = _packet_loss_cause(snap)
        return cause, conf, pkt_ev, "Switch to ethernet"

    # 3. Wi-Fi weak — audio streaming is sensitive to intermittent drops
    if snap.wifi_weak:
        evidence.append(f"Wi-Fi signal: {snap.wifi_signal_pct}% (weak)")
        evidence.append("Weak signal causes brief drops which interrupt audio stream")
        return CAUSE_WIFI_INTERFERENCE, 75, evidence, "Move closer to router or use ethernet"

    # 4. CPU
    if snap.cpu_high:
        evidence.append(f"CPU at {snap.cpu_pct:.0f}%")
        return CAUSE_LOCAL_CONTENTION, 60, evidence, "Close other applications"

    # 5. Default — server side (common with Spotify CDN)
    evidence.append("Audio streams require very little bandwidth — network appears healthy")
    evidence.append("Issue likely server-side (CDN or account throttling)")
    return CAUSE_SERVER_THROTTLE, 55, evidence, "Check Spotify status at status.spotify.com"


def _diagnose_default(snap: SignalSnapshot, alert: Alert) -> tuple:
    """
    Generic tree for web browsing and unknown app-classes.
    """
    evidence = []

    if snap.dns_slow:
        evidence.append(f"DNS: {snap.dns_ms:.0f}ms — slow DNS delays every new page load")
        return CAUSE_DNS_PROBLEM, 78, evidence, "Switch DNS to 8.8.8.8"

    if snap.retransmit_high:
        cause, conf, pkt_ev = _packet_loss_cause(snap)
        return cause, conf, pkt_ev, "Check Wi-Fi signal or contact ISP"

    if snap.rtt_sustained_high:
        evidence.append(f"RTT sustained at {snap.rtt_ms:.0f}ms vs {snap.rtt_baseline_ms:.0f}ms baseline")
        return CAUSE_ROUTE_CHANGE, 62, evidence, "Restart router or wait for route recovery"

    if snap.rtt_jump:
        evidence.append(f"RTT jumped to {snap.rtt_ms:.0f}ms")
        return CAUSE_BUFFERBLOAT, 60, evidence, "Reduce concurrent network usage"

    if snap.cpu_high:
        evidence.append(f"CPU at {snap.cpu_pct:.0f}%")
        return CAUSE_LOCAL_CONTENTION, 65, evidence, "Close background applications"

    if _network_looks_healthy(snap):
        evidence.append("All network signals normal")
        return CAUSE_SERVER_THROTTLE, 50, evidence, "Check service status page"

    return CAUSE_UNKNOWN, 25, ["Signals incomplete"], "Check internet connection manually"


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTER — maps app-class label to the right decision function
# ══════════════════════════════════════════════════════════════════════════════
def _route_to_tree(app_class: str):
    ac = app_class.lower()
    if "gaming"    in ac: return _diagnose_gaming
    if "video"     in ac: return _diagnose_video_streaming
    if "download"  in ac: return _diagnose_download
    if "voip"      in ac or "conference" in ac: return _diagnose_voip
    if "audio"     in ac: return _diagnose_audio_streaming
    return _diagnose_default


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ROOT CAUSE ENGINE CLASS
# ══════════════════════════════════════════════════════════════════════════════
class RootCauseEngine:
    """
    Usage:
        rce = RootCauseEngine()
        root_cause = rce.analyse(alert, signal_snapshot)
    """

    CAUSE_CSV = "root_cause_log.csv"
    CSV_FIELDS = [
        "timestamp", "pid", "process", "app_class",
        "severity", "cause", "confidence",
        "secondary_cause", "evidence", "recommendation",
        "rtt_ms", "jitter_ms", "rtt_baseline_ms",
        "rtt_jump", "rtt_sustained",
        "retransmit_rate", "dns_ms",
        "wifi_pct", "cpu_pct",
    ]

    def __init__(self):
        self._init_csv()

    def analyse(self, alert: Alert, snap: SignalSnapshot) -> RootCause:
        """
        Run the per-app-class decision tree and return a RootCause.
        Always returns something — never raises.
        """
        try:
            tree_fn = _route_to_tree(alert.app_class)
            cause, confidence, evidence, recommendation = tree_fn(snap, alert)
        except Exception as e:
            cause          = CAUSE_UNKNOWN
            confidence     = 0
            evidence       = [f"Engine error: {e}"]
            recommendation = "Check logs"

        rc = RootCause(
            alert=alert,
            cause=cause,
            confidence=confidence,
            evidence=evidence,
            recommendation=recommendation,
        )

        self._log(rc, snap)
        return rc

    # ── CSV logging ───────────────────────────────────────────────────────────
    def _init_csv(self):
        if not os.path.isfile(self.CAUSE_CSV):
            with open(self.CAUSE_CSV, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=self.CSV_FIELDS).writeheader()

    def _log(self, rc: RootCause, snap: SignalSnapshot):
        with open(self.CAUSE_CSV, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=self.CSV_FIELDS).writerow({
                "timestamp":       rc.timestamp,
                "pid":             rc.alert.pid,
                "process":         rc.alert.proc,
                "app_class":       rc.alert.app_class,
                "severity":        rc.alert.severity,
                "cause":           rc.cause,
                "confidence":      rc.confidence,
                "secondary_cause": rc.secondary_cause or "",
                "evidence":        " | ".join(rc.evidence),
                "recommendation":  rc.recommendation,
                "rtt_ms":          snap.rtt_ms,
                "jitter_ms":       snap.jitter_ms,
                "rtt_baseline_ms": snap.rtt_baseline_ms,
                "rtt_jump":        snap.rtt_jump,
                "rtt_sustained":   snap.rtt_sustained_high,
                "retransmit_rate": snap.retransmit_rate,
                "dns_ms":          snap.dns_ms,
                "wifi_pct":        snap.wifi_signal_pct,
                "cpu_pct":         snap.cpu_pct,
            })