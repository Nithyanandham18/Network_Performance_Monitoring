import csv
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# sustain_secs are in ENGINE CALLS (Assuming REFRESH_INTERVAL = 2s)
# 5 calls = 10s | 10 calls = 20s | 15 calls = 30s
CLASS_CONFIG = {
    "Gaming":                     {"drop_threshold": 0.50, "sustain_secs": 5,  "min_baseline_kbps": 10.0,  "ewma_alpha": 0.20},
    "Video Streaming":            {"drop_threshold": 0.35, "sustain_secs": 10, "min_baseline_kbps": 500.0, "ewma_alpha": 0.10},
    "Audio Streaming":            {"drop_threshold": 0.40, "sustain_secs": 10, "min_baseline_kbps": 50.0,  "ewma_alpha": 0.10},
    "Large File Download":        {"drop_threshold": 0.30, "sustain_secs": 25, "min_baseline_kbps": 3000.0,"ewma_alpha": 0.08},
    "Download / Rich Streaming":  {"drop_threshold": 0.40, "sustain_secs": 10, "min_baseline_kbps": 200.0, "ewma_alpha": 0.12},
    "VoIP/Chat":                  {"drop_threshold": 0.45, "sustain_secs": 5,  "min_baseline_kbps": 20.0,  "ewma_alpha": 0.15},
    "Video Conference":           {"drop_threshold": 0.40, "sustain_secs": 5,  "min_baseline_kbps": 100.0, "ewma_alpha": 0.12},
    "default":                    {"drop_threshold": 0.40, "sustain_secs": 10, "min_baseline_kbps": 500.0,  "ewma_alpha": 0.12},
}

@dataclass
class FlowState:
    pid:           int
    proc:          str
    app_class:     str
    ewma_kbps:     float = 0.0
    ewma_ready:    bool  = False
    samples_seen:  int   = 0
    degraded_secs: int   = 0   # Counts engine loops (calls)
    alert_active:  bool  = False
    severity:      int   = 0
    alert_start:   Optional[float] = None

@dataclass
class Alert:
    pid:           int
    proc:          str
    app_class:     str
    severity:      int
    current_kbps:  float
    baseline_kbps: float
    degraded_secs: int
    reason:        str
    timestamp:     str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def _config_for(classification: str) -> dict:
    cl = classification.lower()
    if "gaming" in cl: return CLASS_CONFIG["Gaming"]
    if any(x in cl for x in ["youtube", "netflix", "video streaming", "twitch", "hotstar"]):
        return CLASS_CONFIG["Video Streaming"]
    if "audio" in cl or "spotify" in cl: return CLASS_CONFIG["Audio Streaming"]
    if "large file" in cl: return CLASS_CONFIG["Large File Download"]
    if "download" in cl: return CLASS_CONFIG["Download / Rich Streaming"]
    if "voip" in cl or "chat" in cl: return CLASS_CONFIG["VoIP/Chat"]
    if "conference" in cl: return CLASS_CONFIG["Video Conference"]
    return CLASS_CONFIG["default"]

def _class_name(classification: str) -> str:
    cl = classification.lower()
    if "gaming" in cl: return "Gaming"
    if "youtube" in cl: return "Video Streaming (YouTube)"
    if "netflix" in cl: return "Video Streaming (Netflix)"
    if "video" in cl: return "Video Streaming"
    if "audio" in cl: return "Audio Streaming"
    if "large file" in cl: return "Large File Download"
    if "download" in cl: return "Download"
    if "voip" in cl: return "VoIP/Chat"
    if "conference" in cl: return "Video Conference"
    return "Web/Other"

def _compute_severity(current_kbps: float, baseline_kbps: float) -> int:
    if baseline_kbps <= 0: return 0
    ratio = current_kbps / baseline_kbps
    if ratio >= 1.0: return 0
    drop = 1.0 - ratio
    return min(int((drop ** 0.7) * 100), 100)

def _update_ewma(state: FlowState, avg_kbps: float, alpha: float) -> float:
    state.samples_seen += 1
    if state.samples_seen <= 10:
        state.ewma_kbps = ((state.ewma_kbps * (state.samples_seen - 1) + avg_kbps) / state.samples_seen)
        if state.samples_seen == 10: state.ewma_ready = True
        return state.ewma_kbps
    if state.degraded_secs == 0:
        state.ewma_kbps = alpha * avg_kbps + (1 - alpha) * state.ewma_kbps
    return state.ewma_kbps

class DegradationEngine:
    ALERT_CSV = "degradation_alerts.csv"
    CSV_FIELDS = ["timestamp", "pid", "process", "app_class", "severity", "current_kbps", "baseline_kbps", "degraded_calls", "reason"]

    def __init__(self):
        self._states: dict[int, FlowState] = {}
        self._init_csv()

    def _init_csv(self):
        if not os.path.isfile(self.ALERT_CSV):
            with open(self.ALERT_CSV, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=self.CSV_FIELDS).writeheader()

    def _log_alert(self, alert: Alert):
        with open(self.ALERT_CSV, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=self.CSV_FIELDS).writerow({
                "timestamp": alert.timestamp, "pid": alert.pid, "process": alert.proc,
                "app_class": alert.app_class, "severity": alert.severity,
                "current_kbps": f"{alert.current_kbps:.1f}", "baseline_kbps": f"{alert.baseline_kbps:.1f}",
                "degraded_calls": alert.degraded_secs, "reason": alert.reason,
            })
            f.flush()
            os.fsync(f.fileno())

    def update(self, pid: int, proc: str, classification: str, current_kbps: float, avg_kbps: float) -> Optional[Alert]:
        state = self._get_or_create(pid, proc, classification)
        cfg = _config_for(classification)

        if avg_kbps < 15.0:
            state.degraded_secs = 0
            state.alert_active = False
            state.alert_start = None
            _update_ewma(state, avg_kbps, cfg["ewma_alpha"])
            return None

        baseline = _update_ewma(state, avg_kbps, cfg["ewma_alpha"])
        if not state.ewma_ready or baseline < cfg["min_baseline_kbps"]:
            return None

        state.severity = _compute_severity(avg_kbps, baseline)
        is_degraded = (avg_kbps < baseline * cfg["drop_threshold"])

        if is_degraded:
            state.degraded_secs += 1
            if state.alert_start is None: state.alert_start = time.time()
        else:
            state.degraded_secs = 0
            state.alert_active = False
            state.alert_start = None
            return None

        if state.degraded_secs >= cfg["sustain_secs"]:
            if not state.alert_active:
                state.alert_active = True
                alert = self._build_alert(state, avg_kbps, baseline, classification)
                self._log_alert(alert)
                return alert
            if state.degraded_secs % 15 == 0:
                alert = self._build_alert(state, avg_kbps, baseline, classification)
                self._log_alert(alert)
                return alert
        return None

    def _get_or_create(self, pid: int, proc: str, classification: str) -> FlowState:
        if pid not in self._states:
            self._states[pid] = FlowState(pid=pid, proc=proc, app_class=_class_name(classification))
        return self._states[pid]

    def _build_alert(self, state: FlowState, avg_kbps: float, baseline_kbps: float, classification: str) -> Alert:
        drop_pct = int((1 - avg_kbps / max(baseline_kbps, 0.001)) * 100)
        reason = f"{state.app_class} dropped {drop_pct}% below baseline"
        return Alert(pid=state.pid, proc=state.proc, app_class=state.app_class, severity=state.severity, current_kbps=avg_kbps, baseline_kbps=baseline_kbps, degraded_secs=state.degraded_secs, reason=reason)

    # --- UI HELPER METHODS ---
    def get_state(self, pid: int) -> Optional[FlowState]:
        return self._states.get(pid)

    def all_states(self) -> dict:
        return self._states

    def remove_pid(self, pid: int):
        self._states.pop(pid, None)