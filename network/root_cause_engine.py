import csv
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from signal_collector import SignalSnapshot
from degradation_engine import Alert

@dataclass
class RootCause:
    alert:          Alert
    cause:          str        
    confidence:     int        
    evidence:       list       
    recommendation: str        
    secondary_cause: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

CAUSE_WIFI_INTERFERENCE  = "Wi-Fi interference"
CAUSE_ISP_PACKET_LOSS    = "ISP / upstream packet loss"
CAUSE_BUFFERBLOAT        = "Bufferbloat / network congestion"
CAUSE_ROUTE_CHANGE       = "Network route change"
CAUSE_DNS_PROBLEM        = "DNS slowness or failure"
CAUSE_SERVER_THROTTLE    = "Server-side throttling"
CAUSE_LOCAL_CONTENTION   = "Local resource contention"
CAUSE_CONNECTION_DROP    = "Intermittent connection drop"
CAUSE_UNKNOWN            = "Unknown — insufficient signal data"

def _network_looks_healthy(snap: SignalSnapshot) -> bool:
    return (not snap.rtt_jump and not snap.rtt_sustained_high and not snap.retransmit_high 
            and not snap.dns_slow and not snap.wifi_weak and snap.rtt_ms < 150)

def _packet_loss_cause(snap: SignalSnapshot) -> tuple:
    evidence = [f"TCP retransmissions: {snap.retransmit_rate:.1f}/s (threshold 5/s)"]
    if snap.wifi_signal_pct >= 0:
        evidence.append(f"Wi-Fi signal: {snap.wifi_signal_pct}%")
        if snap.wifi_weak:
            evidence.append("Weak Wi-Fi signal is causing wireless packet drops")
            return CAUSE_WIFI_INTERFERENCE, 85, evidence
        else:
            evidence.append("Wi-Fi signal is adequate — loss is beyond the router")
            return CAUSE_ISP_PACKET_LOSS, 78, evidence
    else:
        evidence.append("Ethernet connection — packet loss is beyond your router")
        return CAUSE_ISP_PACKET_LOSS, 80, evidence

def _diagnose_gaming(snap: SignalSnapshot, alert: Alert) -> tuple:
    evidence = []
    if snap.jitter_ms > 20:
        evidence.append(f"High jitter: {snap.jitter_ms:.1f}ms (>20ms hurts gaming)")
        if snap.retransmit_high:
            evidence.append(f"Also seeing retransmissions: {snap.retransmit_rate:.1f}/s")
            cause, conf, pkt_ev = _packet_loss_cause(snap)
            return cause, conf, evidence + pkt_ev, "Reduce Wi-Fi interference or contact ISP about packet loss"
        if snap.rtt_jump or snap.rtt_sustained_high:
            evidence.append(f"RTT elevated: {snap.rtt_ms:.0f}ms (baseline: {snap.rtt_baseline_ms:.0f}ms)")
            if snap.rtt_sustained_high:
                evidence.append("RTT has been elevated for over 30s — route change likely")
                return CAUSE_ROUTE_CHANGE, 72, evidence, "Run tracert to game server to confirm route change"
            return CAUSE_BUFFERBLOAT, 75, evidence, "Enable QoS on your router, prioritise gaming traffic"
        if snap.wifi_signal_pct >= 0:
            evidence.append(f"Wi-Fi signal: {snap.wifi_signal_pct}%")
            if snap.wifi_weak:
                return CAUSE_WIFI_INTERFERENCE, 80, evidence, "Move closer to router or use ethernet"
            return CAUSE_BUFFERBLOAT, 68, evidence, "Enable QoS / reduce other traffic during gaming"
        return CAUSE_BUFFERBLOAT, 65, evidence, "Check router QoS settings"
    if snap.retransmit_high:
        cause, conf, pkt_ev = _packet_loss_cause(snap)
        return cause, conf, pkt_ev, "Use ethernet, or contact ISP about packet loss"
    if snap.rtt_jump:
        evidence.append(f"RTT jumped to {snap.rtt_ms:.0f}ms (baseline {snap.rtt_baseline_ms:.0f}ms)")
        if snap.rtt_sustained_high:
            evidence.append("Sustained for >30s — route likely changed")
            return CAUSE_ROUTE_CHANGE, 70, evidence, "Wait for route to recover or restart router"
        return CAUSE_BUFFERBLOAT, 62, evidence, "Reduce other network activity"
    if snap.cpu_high:
        evidence.append(f"CPU at {snap.cpu_pct:.0f}% — local processing bottleneck")
        return CAUSE_LOCAL_CONTENTION, 74, evidence, "Close background applications"
    if _network_looks_healthy(snap):
        evidence.append(f"RTT normal ({snap.rtt_ms:.0f}ms), no packet loss, no jitter")
        evidence.append("All local signals healthy — issue likely on game server side")
        return CAUSE_SERVER_THROTTLE, 55, evidence, "Check game server status page"
    return CAUSE_UNKNOWN, 30, ["Insufficient signal data"], "Verify network manually"

def _diagnose_video_streaming(snap: SignalSnapshot, alert: Alert) -> tuple:
    evidence = []
    if snap.retransmit_high:
        cause, conf, pkt_ev = _packet_loss_cause(snap)
        return cause, conf, pkt_ev + [f"Packet loss is draining the video buffer (severity {alert.severity})"], "Switch to ethernet or move closer to router"
    if snap.dns_slow:
        evidence.append(f"DNS resolution taking {snap.dns_ms:.0f}ms (>2000ms)")
        evidence.append("Video CDN uses many short-lived connections — slow DNS blocks each one")
        return CAUSE_DNS_PROBLEM, 82, evidence, "Switch DNS to 8.8.8.8 or 1.1.1.1"
    if snap.rtt_sustained_high:
        evidence.append(f"RTT elevated for >30s: {snap.rtt_ms:.0f}ms vs baseline {snap.rtt_baseline_ms:.0f}ms")
        evidence.append("CDN node may have changed or a backbone route degraded")
        return CAUSE_ROUTE_CHANGE, 68, evidence, "Wait for CDN rerouting to stabilise"
    if snap.rtt_jump:
        evidence.append(f"RTT jumped to {snap.rtt_ms:.0f}ms (baseline {snap.rtt_baseline_ms:.0f}ms)")
        evidence.append("High RTT slows TCP window — video segments arrive too slowly")
        return CAUSE_BUFFERBLOAT, 70, evidence, "Reduce concurrent downloads or enable router QoS"
    if snap.cpu_high:
        evidence.append(f"CPU at {snap.cpu_pct:.0f}%")
        return CAUSE_LOCAL_CONTENTION, 65, evidence, "Close other applications consuming CPU"
    if _network_looks_healthy(snap):
        evidence.append(f"RTT: {snap.rtt_ms:.0f}ms, no packet loss, DNS fast")
        evidence.append(f"Network healthy — speed dropped {100 - int(alert.current_kbps/max(alert.baseline_kbps,1)*100)}% below baseline")
        evidence.append("CDN or ISP may be throttling this stream")
        return CAUSE_SERVER_THROTTLE, 60, evidence, "Try a VPN to confirm throttling"
    return CAUSE_UNKNOWN, 30, ["Insufficient signal data"], "Check network connection manually"

def _diagnose_download(snap: SignalSnapshot, alert: Alert) -> tuple:
    evidence = []
    if snap.retransmit_high:
        cause, conf, pkt_ev = _packet_loss_cause(snap)
        return cause, conf, pkt_ev + ["Packet loss is causing TCP to reduce its window size"], "Use ethernet for large downloads"
    if snap.dns_slow:
        evidence.append(f"DNS slow: {snap.dns_ms:.0f}ms")
        return CAUSE_DNS_PROBLEM, 70, evidence, "Switch DNS to 1.1.1.1"
    if snap.rtt_sustained_high:
        evidence.append(f"RTT sustained high: {snap.rtt_ms:.0f}ms vs {snap.rtt_baseline_ms:.0f}ms baseline")
        return CAUSE_ROUTE_CHANGE, 60, evidence, "Try pausing and resuming the download"
    if _network_looks_healthy(snap):
        drop_pct = int((1 - alert.current_kbps / max(alert.baseline_kbps, 1)) * 100)
        evidence.append(f"Speed dropped {drop_pct}% below baseline")
        evidence.append("No packet loss, normal RTT, DNS healthy")
        evidence.append("ISPs commonly throttle large sustained downloads")
        return CAUSE_SERVER_THROTTLE, 65, evidence, "Try download at off-peak hours or use a VPN"
    return CAUSE_UNKNOWN, 30, ["Insufficient signal data"], "Check download source server status"

def _diagnose_default(snap: SignalSnapshot, alert: Alert) -> tuple:
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

def _route_to_tree(app_class: str):
    ac = app_class.lower()
    if "gaming"    in ac: return _diagnose_gaming
    if "video"     in ac: return _diagnose_video_streaming
    if "download"  in ac: return _diagnose_download
    return _diagnose_default

class RootCauseEngine:
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
        try:
            tree_fn = _route_to_tree(alert.app_class)
            cause, confidence, evidence, recommendation = tree_fn(snap, alert)
        except Exception as e:
            cause          = CAUSE_UNKNOWN
            confidence     = 0
            evidence       = [f"Engine error: {e}"]
            recommendation = "Check logs"

        rc = RootCause(alert=alert, cause=cause, confidence=confidence, evidence=evidence, recommendation=recommendation)
        self._log(rc, snap)
        return rc

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
            f.flush()
            os.fsync(f.fileno())