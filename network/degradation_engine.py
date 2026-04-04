import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# TRIGGER-HAPPY CONFIG: All sustain timers set to 2 seconds for instant alerts!
CLASS_CONFIG = {
    "Gaming": {"drop_threshold": 0.50, "sustain_secs": 2, "min_baseline_kbps": 10.0, "ewma_alpha": 0.15},
    "Video Streaming": {"drop_threshold": 0.30, "sustain_secs": 2, "min_baseline_kbps": 200.0, "ewma_alpha": 0.08},
    "Audio Streaming": {"drop_threshold": 0.35, "sustain_secs": 2, "min_baseline_kbps": 50.0, "ewma_alpha": 0.08},
    "Large File Download": {"drop_threshold": 0.40, "sustain_secs": 2, "min_baseline_kbps": 100.0, "ewma_alpha": 0.10}, 
    "Download / Rich Streaming": {"drop_threshold": 0.40, "sustain_secs": 2, "min_baseline_kbps": 80.0, "ewma_alpha": 0.10},
    "VoIP/Chat": {"drop_threshold": 0.45, "sustain_secs": 2, "min_baseline_kbps": 20.0, "ewma_alpha": 0.12},
    "Video Conference": {"drop_threshold": 0.40, "sustain_secs": 2, "min_baseline_kbps": 100.0, "ewma_alpha": 0.10},
    "default": {"drop_threshold": 0.35, "sustain_secs": 2, "min_baseline_kbps": 30.0, "ewma_alpha": 0.10},
}

@dataclass
class FlowState:
    pid: int
    proc: str
    app_class: str
    ewma_kbps: float = 0.0
    ewma_ready: bool = False
    samples_seen: int = 0
    degraded_secs: int = 0
    alert_active: bool = False
    severity: int = 0
    alert_start: Optional[float] = None

@dataclass
class Alert:
    pid: int
    proc: str
    app_class: str
    severity: int
    current_kbps: float
    baseline_kbps: float
    degraded_secs: int
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def _config_for(classification: str) -> dict:
    cl = classification.lower()
    if "gaming" in cl: return CLASS_CONFIG["Gaming"]
    if "youtube" in cl or "netflix" in cl or "video streaming" in cl or "twitch" in cl: return CLASS_CONFIG["Video Streaming"]
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

def _compute_severity(current_kbps: float, baseline_kbps: float, cfg: dict) -> int:
    if baseline_kbps <= 0: return 0
    ratio = current_kbps / baseline_kbps
    if ratio >= 1.0: return 0
    drop = 1.0 - ratio
    return min(int((drop ** 0.7) * 100), 100)

def _update_ewma(state: FlowState, current_kbps: float, alpha: float) -> float:
    state.samples_seen += 1
    if state.samples_seen <= 10:
        state.ewma_kbps = ((state.ewma_kbps * (state.samples_seen - 1) + current_kbps) / state.samples_seen)
        if state.samples_seen == 10: state.ewma_ready = True
        return state.ewma_kbps
    if not state.alert_active:
        state.ewma_kbps = alpha * current_kbps + (1 - alpha) * state.ewma_kbps
    return state.ewma_kbps

class DegradationEngine:
    ALERT_CSV = "degradation_alerts.csv"

    def __init__(self):
        self._states: dict[int, FlowState] = {}

    def update(self, pid: int, proc: str, classification: str, current_kbps: float) -> Optional[Alert]:
        state = self._get_or_create(pid, proc, classification)
        cfg = _config_for(classification)
        baseline = _update_ewma(state, current_kbps, cfg["ewma_alpha"])

        if not state.ewma_ready or baseline < cfg["min_baseline_kbps"]: return None

        state.severity = _compute_severity(current_kbps, baseline, cfg)
        is_degraded = (current_kbps < baseline * cfg["drop_threshold"])

        if is_degraded:
            state.degraded_secs += 1 # We poll every 1 second
            if state.alert_start is None: state.alert_start = time.time()
        else:
            state.degraded_secs = 0
            state.alert_active = False
            state.alert_start = None
            return None

        if state.degraded_secs >= cfg["sustain_secs"]:
            if not state.alert_active:
                state.alert_active = True
                return self._build_alert(state, current_kbps, baseline, classification)
            if state.degraded_secs % 30 == 0:
                return self._build_alert(state, current_kbps, baseline, classification)
        return None

    def _get_or_create(self, pid: int, proc: str, classification: str) -> FlowState:
        if pid not in self._states:
            self._states[pid] = FlowState(pid=pid, proc=proc, app_class=_class_name(classification))
        return self._states[pid]

    def _build_alert(self, state: FlowState, current_kbps: float, baseline_kbps: float, classification: str) -> Alert:
        drop_pct = int((1 - current_kbps / max(baseline_kbps, 0.001)) * 100)
        reason = f"{state.app_class} dropped {drop_pct}% below baseline ({current_kbps:.0f} kbps vs {baseline_kbps:.0f} kbps normal) for {state.degraded_secs}s"
        return Alert(pid=state.pid, proc=state.proc, app_class=state.app_class, severity=state.severity, current_kbps=current_kbps, baseline_kbps=baseline_kbps, degraded_secs=state.degraded_secs, reason=reason)

    def get_state(self, pid: int) -> Optional[FlowState]:
        return self._states.get(pid)

    def all_states(self) -> dict[int, FlowState]:
        return self._states

    def remove_pid(self, pid: int):
        if pid in self._states:
            del self._states[pid]