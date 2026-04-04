"""
test_root_cause.py  –  Exhaustive unit tests for RootCauseEngine
Run:  python -m pytest test_root_cause.py -v
or:   python test_root_cause.py
"""

import sys, os, unittest
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ── Inline stubs so the test file runs standalone (no psutil / subprocess) ──

@dataclass
class SignalSnapshot:
    rtt_ms:             float = 30.0
    jitter_ms:          float = 2.0
    rtt_baseline_ms:    float = 30.0
    rtt_jump:           bool  = False
    rtt_sustained_high: bool  = False
    retransmit_rate:    float = 0.0
    retransmit_high:    bool  = False
    dns_ms:             float = 50.0
    dns_slow:           bool  = False
    wifi_signal_pct:    int   = 80
    wifi_weak:          bool  = False
    cpu_pct:            float = 20.0
    cpu_high:           bool  = False
    collected_at:       float = 0.0


@dataclass
class Alert:
    pid:           int   = 1234
    proc:          str   = "test_proc"
    app_class:     str   = "Gaming"
    severity:      int   = 50
    current_kbps:  float = 200.0
    baseline_kbps: float = 500.0
    degraded_secs: int   = 10
    reason:        str   = "test"
    timestamp:     str   = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# ── Pull in the engine under test (import from local comp/ directory) ────────

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Patch imports the engine uses so we don't need signal_collector / degradation_engine
import types, importlib

# Create fake modules
for mod_name, cls_list in [
    ("signal_collector",  ["SignalSnapshot"]),
    ("degradation_engine", ["Alert"]),
]:
    fake = types.ModuleType(mod_name)
    for cls_name in cls_list:
        setattr(fake, cls_name, globals()[cls_name])
    sys.modules[mod_name] = fake

import root_cause_engine as rce

CAUSES = dict(
    WIFI      = rce.CAUSE_WIFI_INTERFERENCE,
    ISP       = rce.CAUSE_ISP_PACKET_LOSS,
    BLOAT     = rce.CAUSE_BUFFERBLOAT,
    ROUTE     = rce.CAUSE_ROUTE_CHANGE,
    DNS       = rce.CAUSE_DNS_PROBLEM,
    THROTTLE  = rce.CAUSE_SERVER_THROTTLE,
    LOCAL     = rce.CAUSE_LOCAL_CONTENTION,
    DROP      = rce.CAUSE_CONNECTION_DROP,
    UNKNOWN   = rce.CAUSE_UNKNOWN,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def snap(**kwargs) -> SignalSnapshot:
    """Build a SignalSnapshot; caller supplies only the fields they care about."""
    s = SignalSnapshot()
    for k, v in kwargs.items():
        setattr(s, k, v)
    return s


def alert(app_class="Gaming", **kwargs) -> Alert:
    a = Alert(app_class=app_class)
    for k, v in kwargs.items():
        setattr(a, k, v)
    return a


def run_engine(snap_obj, alert_obj):
    """Call the appropriate private tree function directly (no CSV I/O)."""
    fn = rce._route_to_tree(alert_obj.app_class)
    return fn(snap_obj, alert_obj)   # returns (cause, confidence, evidence, recommendation)


# ════════════════════════════════════════════════════════════════════════════
#  GAMING  (_diagnose_gaming)
# ════════════════════════════════════════════════════════════════════════════

class TestGaming(unittest.TestCase):

    # ── High jitter + retransmissions  →  packet-loss path ──────────────────

    def test_gaming_jitter_retrans_wifi_weak(self):
        """High jitter + retransmissions + weak WiFi  →  Wi-Fi interference"""
        s = snap(jitter_ms=25, retransmit_high=True, retransmit_rate=8,
                 wifi_signal_pct=35, wifi_weak=True)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["WIFI"])
        self.assertGreaterEqual(conf, 70)

    def test_gaming_jitter_retrans_good_wifi(self):
        """High jitter + retransmissions + strong WiFi  →  ISP packet loss"""
        s = snap(jitter_ms=25, retransmit_high=True, retransmit_rate=8,
                 wifi_signal_pct=85, wifi_weak=False)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["ISP"])

    def test_gaming_jitter_retrans_ethernet(self):
        """High jitter + retransmissions + ethernet (no wifi)  →  ISP packet loss"""
        s = snap(jitter_ms=25, retransmit_high=True, retransmit_rate=8,
                 wifi_signal_pct=-1, wifi_weak=False)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["ISP"])

    # ── High jitter + RTT ────────────────────────────────────────────────────

    def test_gaming_jitter_rtt_sustained(self):
        """High jitter + rtt_jump + sustained  →  Route change"""
        s = snap(jitter_ms=25, rtt_jump=True, rtt_sustained_high=True,
                 rtt_ms=250, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["ROUTE"])

    def test_gaming_jitter_rtt_not_sustained(self):
        """High jitter + rtt_jump (not sustained)  →  Bufferbloat"""
        s = snap(jitter_ms=25, rtt_jump=True, rtt_sustained_high=False,
                 rtt_ms=200, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["BLOAT"])

    # ── High jitter + weak wifi (no retrans, no rtt jump) ───────────────────

    def test_gaming_jitter_weak_wifi_no_retrans(self):
        """High jitter + weak WiFi + no retransmissions  →  Wi-Fi interference"""
        s = snap(jitter_ms=25, wifi_signal_pct=40, wifi_weak=True,
                 retransmit_high=False, rtt_jump=False)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["WIFI"])

    def test_gaming_jitter_good_wifi_no_retrans(self):
        """High jitter + good WiFi + no other issues  →  Bufferbloat"""
        s = snap(jitter_ms=25, wifi_signal_pct=80, wifi_weak=False,
                 retransmit_high=False, rtt_jump=False)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["BLOAT"])

    # ── No high jitter ───────────────────────────────────────────────────────

    def test_gaming_no_jitter_retrans_wifi(self):
        """No jitter, retransmissions present, weak WiFi  →  Wi-Fi interference"""
        s = snap(jitter_ms=5, retransmit_high=True, retransmit_rate=7,
                 wifi_signal_pct=30, wifi_weak=True)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["WIFI"])

    def test_gaming_no_jitter_retrans_isp(self):
        """No jitter, retransmissions present, good WiFi  →  ISP packet loss"""
        s = snap(jitter_ms=5, retransmit_high=True, retransmit_rate=7,
                 wifi_signal_pct=90, wifi_weak=False)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["ISP"])

    def test_gaming_rtt_jump_sustained(self):
        """No jitter, rtt_jump + sustained  →  Route change"""
        s = snap(jitter_ms=5, rtt_jump=True, rtt_sustained_high=True,
                 rtt_ms=300, rtt_baseline_ms=30, retransmit_high=False)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["ROUTE"])

    def test_gaming_rtt_jump_not_sustained(self):
        """No jitter, rtt_jump only  →  Bufferbloat"""
        s = snap(jitter_ms=5, rtt_jump=True, rtt_sustained_high=False,
                 rtt_ms=150, rtt_baseline_ms=30, retransmit_high=False)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["BLOAT"])

    def test_gaming_high_cpu(self):
        """No network issues, high CPU  →  Local contention"""
        s = snap(jitter_ms=5, cpu_high=True, cpu_pct=92,
                 retransmit_high=False, rtt_jump=False)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["LOCAL"])

    def test_gaming_all_healthy(self):
        """All signals healthy  →  Server throttle"""
        s = snap(jitter_ms=5, rtt_ms=28, rtt_baseline_ms=30,
                 retransmit_high=False, rtt_jump=False, rtt_sustained_high=False,
                 dns_slow=False, wifi_signal_pct=85, wifi_weak=False,
                 cpu_high=False)
        cause, conf, ev, rec = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["THROTTLE"])


# ════════════════════════════════════════════════════════════════════════════
#  VIDEO STREAMING  (_diagnose_video_streaming)
# ════════════════════════════════════════════════════════════════════════════

class TestVideoStreaming(unittest.TestCase):

    def test_video_retrans_weak_wifi(self):
        """Retransmissions + weak WiFi  →  Wi-Fi interference"""
        s = snap(retransmit_high=True, retransmit_rate=9,
                 wifi_signal_pct=30, wifi_weak=True)
        cause, conf, ev, rec = run_engine(s, alert("Video Streaming"))
        self.assertEqual(cause, CAUSES["WIFI"])

    def test_video_retrans_good_wifi(self):
        """Retransmissions + good WiFi  →  ISP packet loss"""
        s = snap(retransmit_high=True, retransmit_rate=9,
                 wifi_signal_pct=90, wifi_weak=False)
        cause, conf, ev, rec = run_engine(s, alert("Video Streaming"))
        self.assertEqual(cause, CAUSES["ISP"])

    def test_video_dns_slow(self):
        """Slow DNS  →  DNS problem"""
        s = snap(retransmit_high=False, dns_slow=True, dns_ms=2500)
        cause, conf, ev, rec = run_engine(s, alert("Video Streaming"))
        self.assertEqual(cause, CAUSES["DNS"])
        self.assertGreaterEqual(conf, 70)

    def test_video_rtt_sustained(self):
        """RTT sustained high  →  Route change"""
        s = snap(retransmit_high=False, dns_slow=False,
                 rtt_sustained_high=True, rtt_ms=400, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Video Streaming"))
        self.assertEqual(cause, CAUSES["ROUTE"])

    def test_video_rtt_jump_not_sustained(self):
        """RTT jump (not sustained)  →  Bufferbloat"""
        s = snap(retransmit_high=False, dns_slow=False,
                 rtt_jump=True, rtt_sustained_high=False,
                 rtt_ms=250, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Video Streaming"))
        self.assertEqual(cause, CAUSES["BLOAT"])

    def test_video_high_cpu(self):
        """High CPU, no network issues  →  Local contention"""
        s = snap(retransmit_high=False, dns_slow=False,
                 rtt_jump=False, rtt_sustained_high=False,
                 cpu_high=True, cpu_pct=90, rtt_ms=30, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Video Streaming"))
        self.assertEqual(cause, CAUSES["LOCAL"])

    def test_video_all_healthy(self):
        """All signals healthy  →  Server throttle"""
        s = snap(retransmit_high=False, dns_slow=False,
                 rtt_jump=False, rtt_sustained_high=False,
                 cpu_high=False, rtt_ms=28, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Video Streaming",
                                                    current_kbps=200,
                                                    baseline_kbps=1000))
        self.assertEqual(cause, CAUSES["THROTTLE"])


# ════════════════════════════════════════════════════════════════════════════
#  DOWNLOAD  (_diagnose_download)
# ════════════════════════════════════════════════════════════════════════════

class TestDownload(unittest.TestCase):

    def test_download_retrans_weak_wifi(self):
        """Retransmissions + weak WiFi  →  Wi-Fi interference"""
        s = snap(retransmit_high=True, retransmit_rate=7,
                 wifi_signal_pct=25, wifi_weak=True)
        cause, conf, ev, rec = run_engine(s, alert("Large File Download"))
        self.assertEqual(cause, CAUSES["WIFI"])

    def test_download_retrans_ethernet(self):
        """Retransmissions + ethernet (wifi=-1)  →  ISP packet loss"""
        s = snap(retransmit_high=True, retransmit_rate=7,
                 wifi_signal_pct=-1, wifi_weak=False)
        cause, conf, ev, rec = run_engine(s, alert("Large File Download"))
        self.assertEqual(cause, CAUSES["ISP"])

    def test_download_dns_slow(self):
        """Slow DNS  →  DNS problem"""
        s = snap(retransmit_high=False, dns_slow=True, dns_ms=3000)
        cause, conf, ev, rec = run_engine(s, alert("Download / Rich Streaming"))
        self.assertEqual(cause, CAUSES["DNS"])

    def test_download_rtt_sustained(self):
        """RTT sustained high  →  Route change"""
        s = snap(retransmit_high=False, dns_slow=False,
                 rtt_sustained_high=True, rtt_ms=500, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Large File Download"))
        self.assertEqual(cause, CAUSES["ROUTE"])

    def test_download_all_healthy(self):
        """All healthy  →  Server throttle"""
        s = snap(retransmit_high=False, dns_slow=False,
                 rtt_jump=False, rtt_sustained_high=False,
                 rtt_ms=25, rtt_baseline_ms=28, cpu_high=False)
        cause, conf, ev, rec = run_engine(s, alert("Large File Download",
                                                    current_kbps=100,
                                                    baseline_kbps=500))
        self.assertEqual(cause, CAUSES["THROTTLE"])


# ════════════════════════════════════════════════════════════════════════════
#  DEFAULT / WEB  (_diagnose_default)
# ════════════════════════════════════════════════════════════════════════════

class TestDefault(unittest.TestCase):

    def test_default_dns_slow(self):
        """Slow DNS wins over everything else in default tree"""
        s = snap(dns_slow=True, dns_ms=2200, retransmit_high=False)
        cause, conf, ev, rec = run_engine(s, alert("Web/Other"))
        self.assertEqual(cause, CAUSES["DNS"])
        self.assertGreaterEqual(conf, 70)

    def test_default_retrans_wifi(self):
        """Retransmissions + weak WiFi  →  Wi-Fi interference"""
        s = snap(dns_slow=False, retransmit_high=True, retransmit_rate=6,
                 wifi_signal_pct=30, wifi_weak=True)
        cause, conf, ev, rec = run_engine(s, alert("Web/Other"))
        self.assertEqual(cause, CAUSES["WIFI"])

    def test_default_retrans_isp(self):
        """Retransmissions + good WiFi  →  ISP packet loss"""
        s = snap(dns_slow=False, retransmit_high=True, retransmit_rate=6,
                 wifi_signal_pct=85, wifi_weak=False)
        cause, conf, ev, rec = run_engine(s, alert("Web/Other"))
        self.assertEqual(cause, CAUSES["ISP"])

    def test_default_rtt_sustained(self):
        """RTT sustained  →  Route change"""
        s = snap(dns_slow=False, retransmit_high=False,
                 rtt_sustained_high=True, rtt_ms=400, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Web/Other"))
        self.assertEqual(cause, CAUSES["ROUTE"])

    def test_default_rtt_jump(self):
        """RTT jump only  →  Bufferbloat"""
        s = snap(dns_slow=False, retransmit_high=False,
                 rtt_jump=True, rtt_sustained_high=False,
                 rtt_ms=200, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Web/Other"))
        self.assertEqual(cause, CAUSES["BLOAT"])

    def test_default_high_cpu(self):
        """High CPU, no network issues  →  Local contention"""
        s = snap(dns_slow=False, retransmit_high=False,
                 rtt_jump=False, rtt_sustained_high=False,
                 cpu_high=True, cpu_pct=91, rtt_ms=30, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Web/Other"))
        self.assertEqual(cause, CAUSES["LOCAL"])

    def test_default_all_healthy(self):
        """All healthy  →  Server throttle"""
        s = snap(dns_slow=False, retransmit_high=False,
                 rtt_jump=False, rtt_sustained_high=False,
                 cpu_high=False, rtt_ms=28, rtt_baseline_ms=30)
        cause, conf, ev, rec = run_engine(s, alert("Web/Other"))
        self.assertEqual(cause, CAUSES["THROTTLE"])


# ════════════════════════════════════════════════════════════════════════════
#  ROUTING / APP-CLASS DISPATCH
# ════════════════════════════════════════════════════════════════════════════

class TestRouting(unittest.TestCase):

    def test_routes_gaming(self):
        self.assertIs(rce._route_to_tree("Gaming"), rce._diagnose_gaming)

    def test_routes_video_streaming(self):
        self.assertIs(rce._route_to_tree("Video Streaming"), rce._diagnose_video_streaming)

    def test_routes_video_streaming_youtube(self):
        self.assertIs(rce._route_to_tree("Video Streaming (YouTube)"), rce._diagnose_video_streaming)

    def test_routes_download(self):
        self.assertIs(rce._route_to_tree("Large File Download"), rce._diagnose_download)

    def test_routes_download_rich(self):
        self.assertIs(rce._route_to_tree("Download / Rich Streaming"), rce._diagnose_download)

    def test_routes_web(self):
        self.assertIs(rce._route_to_tree("Web/Other"), rce._diagnose_default)

    def test_routes_voip(self):
        self.assertIs(rce._route_to_tree("VoIP/Chat"), rce._diagnose_default)

    def test_routes_video_conference(self):
        # Previously buggy: "Video Conference" matched "video" before "conference".
        # Fixed in root_cause_engine.py by moving conference check above video.
        self.assertIs(rce._route_to_tree("Video Conference"), rce._diagnose_default)


# ════════════════════════════════════════════════════════════════════════════
#  CONFIDENCE SANITY  –  confirm conf ranges are plausible
# ════════════════════════════════════════════════════════════════════════════

class TestConfidenceRanges(unittest.TestCase):

    def _conf(self, snap_obj, alert_obj):
        _, conf, _, _ = run_engine(snap_obj, alert_obj)
        return conf

    def test_wifi_confidence_high(self):
        s = snap(retransmit_high=True, retransmit_rate=9,
                 wifi_signal_pct=20, wifi_weak=True)
        self.assertGreaterEqual(self._conf(s, alert("Gaming")), 75)

    def test_isp_confidence_decent(self):
        s = snap(retransmit_high=True, retransmit_rate=9,
                 wifi_signal_pct=-1, wifi_weak=False)
        self.assertGreaterEqual(self._conf(s, alert("Gaming")), 70)

    def test_dns_confidence_high(self):
        s = snap(retransmit_high=False, dns_slow=True, dns_ms=2500)
        self.assertGreaterEqual(self._conf(s, alert("Video Streaming")), 75)

    def test_throttle_confidence_lower(self):
        """Throttle is inferred (no direct signal) so confidence should be < 70"""
        s = snap(rtt_ms=28, rtt_baseline_ms=30)
        conf = self._conf(s, alert("Gaming"))
        self.assertLess(conf, 70)

    def test_all_confidence_between_0_and_100(self):
        scenarios = [
            snap(retransmit_high=True, wifi_signal_pct=20, wifi_weak=True),
            snap(retransmit_high=True, wifi_signal_pct=90),
            snap(dns_slow=True, dns_ms=3000),
            snap(rtt_sustained_high=True, rtt_ms=500, rtt_baseline_ms=30),
            snap(rtt_jump=True, rtt_ms=200, rtt_baseline_ms=30),
            snap(cpu_high=True, cpu_pct=95),
            snap(rtt_ms=28, rtt_baseline_ms=30),
        ]
        app_classes = ["Gaming", "Video Streaming", "Large File Download", "Web/Other"]
        for s in scenarios:
            for ac in app_classes:
                _, conf, _, _ = run_engine(s, alert(ac))
                self.assertGreaterEqual(conf, 0, f"conf<0 for {ac}")
                self.assertLessEqual(conf, 100, f"conf>100 for {ac}")


# ════════════════════════════════════════════════════════════════════════════
#  EVIDENCE STRINGS  –  confirm key fields appear in evidence
# ════════════════════════════════════════════════════════════════════════════

class TestEvidenceContent(unittest.TestCase):

    def test_retrans_rate_in_evidence(self):
        s = snap(retransmit_high=True, retransmit_rate=8, wifi_signal_pct=-1)
        _, _, ev, _ = run_engine(s, alert("Gaming"))
        joined = " ".join(ev)
        self.assertIn("retransmission", joined.lower())

    def test_rtt_values_in_evidence(self):
        s = snap(jitter_ms=25, rtt_jump=True, rtt_ms=300, rtt_baseline_ms=30,
                 rtt_sustained_high=False, retransmit_high=False)
        _, _, ev, _ = run_engine(s, alert("Gaming"))
        joined = " ".join(ev)
        self.assertIn("300", joined)

    def test_dns_ms_in_evidence(self):
        s = snap(dns_slow=True, dns_ms=2500, retransmit_high=False)
        _, _, ev, _ = run_engine(s, alert("Video Streaming"))
        joined = " ".join(ev)
        self.assertIn("2500", joined)

    def test_wifi_pct_in_evidence(self):
        s = snap(retransmit_high=True, retransmit_rate=6,
                 wifi_signal_pct=30, wifi_weak=True)
        _, _, ev, _ = run_engine(s, alert("Gaming"))
        joined = " ".join(ev)
        self.assertIn("30", joined)


# ════════════════════════════════════════════════════════════════════════════
#  PRIORITY / TIEBREAKER ORDERING
# ════════════════════════════════════════════════════════════════════════════

class TestPriority(unittest.TestCase):

    def test_video_retrans_beats_dns(self):
        """Packet loss takes priority over DNS in video tree."""
        s = snap(retransmit_high=True, retransmit_rate=7,
                 dns_slow=True, dns_ms=2500,
                 wifi_signal_pct=85, wifi_weak=False)
        cause, _, _, _ = run_engine(s, alert("Video Streaming"))
        self.assertIn(cause, [CAUSES["WIFI"], CAUSES["ISP"]])

    def test_default_dns_beats_retrans(self):
        """In the default tree DNS is checked first."""
        s = snap(dns_slow=True, dns_ms=2200,
                 retransmit_high=True, retransmit_rate=6)
        cause, _, _, _ = run_engine(s, alert("Web/Other"))
        self.assertEqual(cause, CAUSES["DNS"])

    def test_gaming_jitter_path_before_cpu(self):
        """High jitter + weak wifi overrides CPU in gaming tree."""
        s = snap(jitter_ms=25, wifi_signal_pct=30, wifi_weak=True,
                 cpu_high=True, cpu_pct=92,
                 retransmit_high=False, rtt_jump=False)
        cause, _, _, _ = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["WIFI"])


# ════════════════════════════════════════════════════════════════════════════
#  EDGE CASES
# ════════════════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):

    def test_wifi_borderline_49_pct_is_weak(self):
        """wifi_signal_pct=49 with wifi_weak=True  →  wifi cause"""
        s = snap(retransmit_high=True, retransmit_rate=6,
                 wifi_signal_pct=49, wifi_weak=True)
        cause, _, _, _ = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["WIFI"])

    def test_wifi_exactly_50_pct_not_weak(self):
        """wifi_signal_pct=50 with wifi_weak=False  →  ISP (not wifi)"""
        s = snap(retransmit_high=True, retransmit_rate=6,
                 wifi_signal_pct=50, wifi_weak=False)
        cause, _, _, _ = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["ISP"])

    def test_rtt_sustained_without_jump_video(self):
        """rtt_sustained_high can be True even if rtt_jump is False in current tick."""
        s = snap(retransmit_high=False, dns_slow=False,
                 rtt_jump=False, rtt_sustained_high=True,
                 rtt_ms=250, rtt_baseline_ms=30)
        cause, _, _, _ = run_engine(s, alert("Video Streaming"))
        self.assertEqual(cause, CAUSES["ROUTE"])

    def test_all_flags_true_gaming_jitter_wins(self):
        """When everything is on, jitter+retrans+wifi_weak fires first in gaming."""
        s = snap(jitter_ms=30, retransmit_high=True, retransmit_rate=10,
                 rtt_jump=True, rtt_sustained_high=True, dns_slow=True,
                 wifi_signal_pct=20, wifi_weak=True, cpu_high=True, cpu_pct=95)
        cause, _, _, _ = run_engine(s, alert("Gaming"))
        self.assertEqual(cause, CAUSES["WIFI"])

    def test_no_signals_at_all(self):
        """A completely blank snapshot should still return a cause, not raise."""
        s = SignalSnapshot()   # all defaults — nothing elevated
        try:
            cause, conf, ev, rec = run_engine(s, alert("Web/Other"))
        except Exception as e:
            self.fail(f"Engine raised unexpectedly: {e}")
        self.assertIsInstance(cause, str)
        self.assertIsInstance(conf, int)


# ════════════════════════════════════════════════════════════════════════════
#  RECOMMENDATIONS  –  non-empty and meaningful
# ════════════════════════════════════════════════════════════════════════════

class TestRecommendations(unittest.TestCase):

    def _rec(self, snap_obj, app_class):
        _, _, _, rec = run_engine(snap_obj, alert(app_class))
        return rec

    def test_recommendations_are_non_empty(self):
        combos = [
            (snap(retransmit_high=True, wifi_signal_pct=20, wifi_weak=True), "Gaming"),
            (snap(dns_slow=True, dns_ms=2500), "Video Streaming"),
            (snap(rtt_sustained_high=True, rtt_ms=500, rtt_baseline_ms=30), "Large File Download"),
            (snap(cpu_high=True, cpu_pct=92), "Gaming"),
            (snap(rtt_ms=28, rtt_baseline_ms=30), "Web/Other"),
        ]
        for s, ac in combos:
            rec = self._rec(s, ac)
            self.assertTrue(len(rec) > 5, f"Recommendation too short for {ac}: '{rec}'")

    def test_wifi_recommendation_mentions_ethernet_or_router(self):
        s = snap(retransmit_high=True, retransmit_rate=8,
                 wifi_signal_pct=25, wifi_weak=True)
        rec = self._rec(s, "Gaming").lower()
        self.assertTrue("ethernet" in rec or "router" in rec or "closer" in rec)

    def test_dns_recommendation_mentions_dns_server(self):
        s = snap(dns_slow=True, dns_ms=2500, retransmit_high=False)
        rec = self._rec(s, "Video Streaming").lower()
        self.assertTrue("8.8.8.8" in rec or "1.1.1.1" in rec or "dns" in rec)


# ════════════════════════════════════════════════════════════════════════════
#  SUMMARY PRINTER
# ════════════════════════════════════════════════════════════════════════════

def print_summary():
    """Print a human-readable cause table for all key scenarios."""
    print("\n" + "=" * 72)
    print(f"{'SCENARIO':<42} {'APP CLASS':<22} {'CAUSE'}")
    print("=" * 72)
    scenarios = [
        # (description, snap_kwargs, app_class)
        ("High retrans + weak WiFi",          dict(retransmit_high=True, retransmit_rate=8, wifi_signal_pct=30, wifi_weak=True),   "Gaming"),
        ("High retrans + good WiFi",          dict(retransmit_high=True, retransmit_rate=8, wifi_signal_pct=85),                  "Gaming"),
        ("High retrans + Ethernet",           dict(retransmit_high=True, retransmit_rate=8, wifi_signal_pct=-1),                  "Gaming"),
        ("Jitter + rtt_sustained",            dict(jitter_ms=25, rtt_jump=True, rtt_sustained_high=True, rtt_ms=300, rtt_baseline_ms=30), "Gaming"),
        ("Jitter + rtt_jump only",            dict(jitter_ms=25, rtt_jump=True, rtt_ms=200, rtt_baseline_ms=30),                 "Gaming"),
        ("High CPU only",                     dict(cpu_high=True, cpu_pct=92),                                                    "Gaming"),
        ("All healthy (gaming)",              dict(rtt_ms=28, rtt_baseline_ms=30),                                                "Gaming"),
        ("Slow DNS",                          dict(dns_slow=True, dns_ms=2500, retransmit_high=False),                            "Video Streaming"),
        ("RTT sustained (video)",             dict(rtt_sustained_high=True, rtt_ms=400, rtt_baseline_ms=30, retransmit_high=False, dns_slow=False), "Video Streaming"),
        ("All healthy (video)",               dict(rtt_ms=28, rtt_baseline_ms=30),                                                "Video Streaming"),
        ("Slow DNS (default)",                dict(dns_slow=True, dns_ms=2200),                                                   "Web/Other"),
        ("RTT jump (default)",                dict(rtt_jump=True, rtt_ms=200, rtt_baseline_ms=30),                                "Web/Other"),
        ("RTT sustained (default)",           dict(rtt_sustained_high=True, rtt_ms=400, rtt_baseline_ms=30),                      "Web/Other"),
        ("High CPU (default)",                dict(cpu_high=True, cpu_pct=91),                                                    "Web/Other"),
        ("All healthy (default)",             dict(rtt_ms=28, rtt_baseline_ms=30),                                                "Web/Other"),
        ("Retrans weak WiFi (download)",      dict(retransmit_high=True, retransmit_rate=7, wifi_signal_pct=25, wifi_weak=True),  "Large File Download"),
        ("All healthy (download)",            dict(rtt_ms=25, rtt_baseline_ms=28),                                               "Large File Download"),
    ]
    for desc, skw, ac in scenarios:
        s = snap(**skw)
        a = alert(ac, current_kbps=200, baseline_kbps=1000)
        cause, conf, _, _ = run_engine(s, a)
        print(f"  {desc:<40} {ac:<22} {cause}  [{conf}%]")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    print_summary()
    unittest.main(verbosity=2)