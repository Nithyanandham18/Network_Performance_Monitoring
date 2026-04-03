"""
Degradation Detection Engine
==============================
Plugs into behavioral_classifier.py.

For each active PID the engine:
  1. Maintains an EWMA baseline (smoothed "normal" speed)
  2. Computes a deviation ratio  →  raw severity score 0-100
  3. Passes the score through a per-class sustain gate (debounce)
  4. Fires an alert only when degradation is sustained, not transient
  5. Logs every alert to degradation_alerts.csv

Import and use:
    from degradation_engine import DegradationEngine
    engine = DegradationEngine()
    alert = engine.update(pid, classification, current_kbps)
"""

import csv
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
#  PER-CLASS CONFIG
#  Each app class has its own:
#    - drop_threshold  : fraction of baseline below which we consider degraded
#                        e.g. 0.40 means "if speed < 40% of baseline → degraded"
#    - sustain_secs    : how many consecutive seconds score must stay elevated
#                        before we fire a real alert (the debounce / sustain gate)
#    - min_baseline_kbps : ignore flows that are too slow to be meaningful
#    - ewma_alpha      : smoothing factor for the baseline (lower = slower adapt)
#                        0.05 → heavily smoothed (reacts slowly, stable baseline)
#                        0.20 → reacts faster to new normal
# ══════════════════════════════════════════════════════════════════════════════
CLASS_CONFIG = {
    "Gaming": {
        "drop_threshold":     0.50,   # flag if speed drops below 50% of baseline
        "sustain_secs":       5,       # gaming is real-time: alert after 5 s
        "min_baseline_kbps":  10.0,
        "ewma_alpha":         0.15,
    },
    "Video Streaming": {
        "drop_threshold":     0.30,   # video buffers ahead: flag below 30%
        "sustain_secs":       30,      # give 30 s before calling it a stall
        "min_baseline_kbps":  200.0,
        "ewma_alpha":         0.08,
    },
    "Audio Streaming": {
        "drop_threshold":     0.35,
        "sustain_secs":       20,
        "min_baseline_kbps":  50.0,
        "ewma_alpha":         0.08,
    },
    "Large File Download": {
        "drop_threshold":     0.40,   # flag below 40% of baseline
        "sustain_secs":       60,      # downloads tolerate pauses: 60 s gate
        "min_baseline_kbps":  100.0,
        "ewma_alpha":         0.10,
    },
    "Download / Rich Streaming": {
        "drop_threshold":     0.40,
        "sustain_secs":       45,
        "min_baseline_kbps":  80.0,
        "ewma_alpha":         0.10,
    },
    "VoIP/Chat": {
        "drop_threshold":     0.45,
        "sustain_secs":       8,
        "min_baseline_kbps":  20.0,
        "ewma_alpha":         0.12,
    },
    "Video Conference": {
        "drop_threshold":     0.40,
        "sustain_secs":       10,
        "min_baseline_kbps":  100.0,
        "ewma_alpha":         0.10,
    },
    # Catch-all for browsers doing general web / unknown
    "default": {
        "drop_threshold":     0.35,
        "sustain_secs":       30,
        "min_baseline_kbps":  30.0,
        "ewma_alpha":         0.10,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class FlowState:
    """All detection state for one PID."""
    pid:              int
    proc:             str
    app_class:        str

    # EWMA baseline (smoothed normal kbps)
    ewma_kbps:        float = 0.0
    ewma_ready:       bool  = False      # True once baseline has warmed up
    samples_seen:     int   = 0

    # Sustain gate: consecutive degraded seconds
    degraded_secs:    int   = 0
    alert_active:     bool  = False      # True while an ongoing alert is open

    # Last severity score (0-100)
    severity:         int   = 0

    # Timestamp of when the current alert started
    alert_start:      Optional[float] = None


@dataclass
class Alert:
    """Returned when the engine fires an alert."""
    pid:          int
    proc:         str
    app_class:    str
    severity:     int          # 0-100
    current_kbps: float
    baseline_kbps: float
    degraded_secs: int
    reason:       str          # human-readable explanation
    timestamp:    str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER: map a classification label to a config key
# ══════════════════════════════════════════════════════════════════════════════
def _config_for(classification: str) -> dict:
    """
    Map the free-text classification string from the classifier to one of
    the config keys. Falls back to 'default'.
    """
    cl = classification.lower()
    if "gaming"               in cl: return CLASS_CONFIG["Gaming"]
    if "youtube" in cl or "netflix" in cl or "video streaming" in cl or "twitch" in cl:
        return CLASS_CONFIG["Video Streaming"]
    if "audio" in cl or "spotify" in cl: return CLASS_CONFIG["Audio Streaming"]
    if "large file"           in cl: return CLASS_CONFIG["Large File Download"]
    if "download"             in cl: return CLASS_CONFIG["Download / Rich Streaming"]
    if "voip" in cl or "chat" in cl: return CLASS_CONFIG["VoIP/Chat"]
    if "conference"           in cl: return CLASS_CONFIG["Video Conference"]
    return CLASS_CONFIG["default"]


def _class_name(classification: str) -> str:
    """Return a clean short class name for the alert."""
    cl = classification.lower()
    if "gaming"    in cl: return "Gaming"
    if "youtube"   in cl: return "Video Streaming (YouTube)"
    if "netflix"   in cl: return "Video Streaming (Netflix)"
    if "video"     in cl: return "Video Streaming"
    if "audio"     in cl: return "Audio Streaming"
    if "large file" in cl: return "Large File Download"
    if "download"  in cl: return "Download"
    if "voip"      in cl: return "VoIP/Chat"
    if "conference" in cl: return "Video Conference"
    return "Web/Other"


# ══════════════════════════════════════════════════════════════════════════════
#  SEVERITY SCORER
# ══════════════════════════════════════════════════════════════════════════════
def _compute_severity(current_kbps: float, baseline_kbps: float, cfg: dict) -> int:
    """
    Convert a deviation into a 0-100 severity score.

    Score is 0 when current >= baseline (healthy).
    Score reaches 100 when current == 0 (total stall).

    We use a non-linear curve so that:
      - Mild drops (80% of baseline)  → score ~10   (low)
      - Medium drops (50% of baseline) → score ~45  (medium)
      - Severe drops (< 20% baseline)  → score ~85+ (high)
    """
    if baseline_kbps <= 0:
        return 0

    ratio = current_kbps / baseline_kbps    # 1.0 = healthy, 0.0 = stalled

    if ratio >= 1.0:
        return 0

    # Invert and apply a square-root curve for non-linear scaling
    drop = 1.0 - ratio          # 0 = healthy, 1 = fully stalled
    score = int((drop ** 0.7) * 100)
    return min(score, 100)


# ══════════════════════════════════════════════════════════════════════════════
#  EWMA UPDATER
# ══════════════════════════════════════════════════════════════════════════════
def _update_ewma(state: FlowState, current_kbps: float, alpha: float) -> float:
    """
    Update the EWMA baseline.

    During warm-up (first 10 samples) we use a simple running average so
    the baseline isn't dragged down by early zeros.
    After warm-up, standard EWMA applies.

    Only updates the baseline when the flow is NOT already degraded — this
    prevents a sustained drop from becoming the new "normal".
    """
    state.samples_seen += 1

    # Warm-up phase: simple average
    if state.samples_seen <= 10:
        state.ewma_kbps = (
            (state.ewma_kbps * (state.samples_seen - 1) + current_kbps)
            / state.samples_seen
        )
        if state.samples_seen == 10:
            state.ewma_ready = True
        return state.ewma_kbps

    # Post-warm-up: only update baseline if the flow seems healthy
    # (i.e. not already in a degraded state) — avoids drift during an outage
    if not state.alert_active:
        state.ewma_kbps = alpha * current_kbps + (1 - alpha) * state.ewma_kbps

    return state.ewma_kbps


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENGINE CLASS
# ══════════════════════════════════════════════════════════════════════════════
class DegradationEngine:
    """
    Call engine.update(pid, classification, current_kbps) every second.
    Returns an Alert object when degradation is confirmed, else None.

    Example:
        engine = DegradationEngine()
        while True:
            for pid, data in get_active_flows().items():
                alert = engine.update(pid, data['classification'], data['kbps'])
                if alert:
                    print(f"ALERT: {alert.proc} — {alert.reason}")
            time.sleep(1)
    """

    ALERT_CSV = "degradation_alerts.csv"
    CSV_FIELDS = [
        "timestamp", "pid", "process", "app_class",
        "severity", "current_kbps", "baseline_kbps",
        "degraded_secs", "reason",
    ]

    def __init__(self):
        self._states: dict[int, FlowState] = {}
        self._init_csv()

    # ── Public API ────────────────────────────────────────────────────────────
    def update(
        self,
        pid:            int,
        proc:           str,
        classification: str,
        current_kbps:   float,
    ) -> Optional[Alert]:
        """
        Feed one second of data for a PID.
        Returns an Alert if degradation is confirmed, else None.
        """
        state = self._get_or_create(pid, proc, classification)
        cfg   = _config_for(classification)

        # Update EWMA baseline
        baseline = _update_ewma(state, current_kbps, cfg["ewma_alpha"])

        # Can't detect yet — still warming up, or baseline too low to matter
        if not state.ewma_ready or baseline < cfg["min_baseline_kbps"]:
            return None

        # Compute severity
        severity = _compute_severity(current_kbps, baseline, cfg)
        state.severity = severity

        # Is the flow degraded this second?
        drop_threshold = cfg["drop_threshold"]
        is_degraded    = (current_kbps < baseline * drop_threshold)

        if is_degraded:
            state.degraded_secs += 1
            if state.alert_start is None:
                state.alert_start = time.time()
        else:
            # Recovery: reset the sustain counter and close open alert
            state.degraded_secs = 0
            state.alert_active  = False
            state.alert_start   = None
            return None

        # ── Sustain gate ─────────────────────────────────────────────────
        if state.degraded_secs >= cfg["sustain_secs"]:
            if not state.alert_active:
                # First time crossing the gate → fire alert
                state.alert_active = True
                alert = self._build_alert(state, current_kbps, baseline, classification)
                self._log_alert(alert)
                return alert
            # Alert already open — return a refresh every 30 s so the UI
            # can show it's still ongoing without spamming logs
            if state.degraded_secs % 30 == 0:
                return self._build_alert(state, current_kbps, baseline, classification)

        return None

    def get_state(self, pid: int) -> Optional[FlowState]:
        """Return the current FlowState for a PID (for display purposes)."""
        return self._states.get(pid)

    def all_states(self) -> dict:
        return dict(self._states)

    def remove_pid(self, pid: int):
        """Call when a PID disappears from the active flow list."""
        self._states.pop(pid, None)

    # ── Internals ─────────────────────────────────────────────────────────────
    def _get_or_create(self, pid: int, proc: str, classification: str) -> FlowState:
        if pid not in self._states:
            self._states[pid] = FlowState(
                pid=pid,
                proc=proc,
                app_class=_class_name(classification),
            )
        return self._states[pid]

    def _build_alert(
        self,
        state:          FlowState,
        current_kbps:   float,
        baseline_kbps:  float,
        classification: str,
    ) -> Alert:
        drop_pct = int((1 - current_kbps / max(baseline_kbps, 0.001)) * 100)
        reason   = (
            f"{state.app_class} dropped {drop_pct}% below baseline "
            f"({current_kbps:.0f} kbps vs {baseline_kbps:.0f} kbps normal) "
            f"for {state.degraded_secs}s"
        )
        return Alert(
            pid=state.pid,
            proc=state.proc,
            app_class=state.app_class,
            severity=state.severity,
            current_kbps=current_kbps,
            baseline_kbps=baseline_kbps,
            degraded_secs=state.degraded_secs,
            reason=reason,
        )

    def _init_csv(self):
        if not os.path.isfile(self.ALERT_CSV):
            with open(self.ALERT_CSV, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=self.CSV_FIELDS).writeheader()

    def _log_alert(self, alert: Alert):
        with open(self.ALERT_CSV, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=self.CSV_FIELDS).writerow({
                "timestamp":     alert.timestamp,
                "pid":           alert.pid,
                "process":       alert.proc,
                "app_class":     alert.app_class,
                "severity":      alert.severity,
                "current_kbps":  f"{alert.current_kbps:.1f}",
                "baseline_kbps": f"{alert.baseline_kbps:.1f}",
                "degraded_secs": alert.degraded_secs,
                "reason":        alert.reason,
            })