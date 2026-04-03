from degradation_engine import DegradationEngine

def feed(engine, pid, speeds, label="Video Streaming (YouTube)"):
    """Feed a list of per-second speeds into the engine. Return list of alerts."""
    alerts = []
    for kbps in speeds:
        alert = engine.update(pid, "chrome.exe", label, kbps)
        if alert:
            alerts.append(alert)
    return alerts

def test_no_false_alert_during_warmup():
    """Engine must stay silent for first 10 samples no matter what."""
    engine = DegradationEngine()
    alerts = feed(engine, pid=1, speeds=[0] * 10)
    assert alerts == [], "FAIL — fired alert during warmup"
    print("PASS — no alert during warmup")

def test_healthy_flow_never_alerts():
    """Steady healthy speed should never trigger anything."""
    engine = DegradationEngine()
    speeds = [1000] * 60          # stable 1000 kbps for 60 seconds
    alerts = feed(engine, pid=2, speeds=speeds)
    assert alerts == [], "FAIL — healthy flow triggered an alert"
    print("PASS — healthy flow never alerted")

def test_transient_blip_ignored():
    """A short 5-second drop must NOT fire — sustain gate is 30s for video."""
    engine = DegradationEngine()
    speeds  = [1000] * 15         # healthy warmup
    speeds += [50]   * 5          # 5-second blip (way below threshold)
    speeds += [1000] * 20         # recovers
    alerts = feed(engine, pid=3, speeds=speeds)
    assert alerts == [], f"FAIL — transient blip fired an alert: {alerts}"
    print("PASS — 5-second blip correctly ignored")

def test_sustained_drop_fires_alert():
    """A drop lasting longer than the sustain gate MUST fire an alert."""
    engine = DegradationEngine()
    speeds  = [1000] * 15         # healthy baseline built up
    speeds += [50]   * 40         # 40-second drop (gate is 30s for video)
    alerts = feed(engine, pid=4, speeds=speeds)
    assert len(alerts) > 0, "FAIL — sustained drop did not fire any alert"
    a = alerts[0]
    print(f"PASS — alert fired: severity={a.severity}, degraded_secs={a.degraded_secs}, reason='{a.reason}'")

def test_alert_fires_at_correct_second():
    """Alert must fire exactly when degraded_secs crosses the gate (30s for video)."""
    engine = DegradationEngine()
    speeds  = [1000] * 15
    speeds += [50]   * 50
    alerts = feed(engine, pid=5, speeds=speeds)
    assert len(alerts) > 0, "FAIL — no alert fired"
    first = alerts[0]
    assert first.degraded_secs >= 30, \
        f"FAIL — alert fired too early at {first.degraded_secs}s (gate is 30s)"
    print(f"PASS — alert fired at degraded_secs={first.degraded_secs} (gate=30s)")

def test_recovery_resets_counter():
    """Drop → recovery → drop again. Second drop must go through full gate again."""
    engine = DegradationEngine()
    speeds  = [1000] * 15         # warmup
    speeds += [50]   * 10         # first drop (not long enough to alert)
    speeds += [1000] * 10         # recovery — counter resets
    speeds += [50]   * 35         # second drop — must wait full 30s again
    alerts = feed(engine, pid=6, speeds=speeds)
    assert len(alerts) > 0, "FAIL — no alert on second drop"
    a = alerts[0]
    assert a.degraded_secs >= 30, \
        f"FAIL — counter was not reset properly, fired at {a.degraded_secs}s"
    print(f"PASS — counter reset on recovery, second drop correctly gated")

def test_gaming_faster_gate():
    """Gaming gate is 5s — alert must fire much faster than video."""
    engine = DegradationEngine()
    speeds  = [500] * 15          # warmup
    speeds += [10]  * 10          # 10-second drop
    alerts = feed(engine, pid=7, speeds=speeds, label="Gaming")
    assert len(alerts) > 0, "FAIL — gaming drop did not alert"
    a = alerts[0]
    assert a.degraded_secs >= 5, "FAIL — fired before 5s gate"
    assert a.degraded_secs < 30, \
        f"FAIL — gaming alert took {a.degraded_secs}s, should be ~5s"
    print(f"PASS — gaming alerted at {a.degraded_secs}s (fast gate working)")

def test_severity_increases_with_drop():
    """Bigger drop should produce a higher severity score."""
    engine1 = DegradationEngine()
    engine2 = DegradationEngine()
    # mild drop: 70% of baseline
    feed(engine1, pid=8,  speeds=[1000]*15 + [700]*35)
    # severe drop: 5% of baseline
    feed(engine2, pid=9,  speeds=[1000]*15 + [50] *35)
    s1 = engine1.get_state(8).severity
    s2 = engine2.get_state(9).severity
    assert s2 > s1, \
        f"FAIL — severe drop scored {s2} but mild drop scored {s1}"
    print(f"PASS — mild drop severity={s1}, severe drop severity={s2} (correct ordering)")

def test_baseline_freezes_during_alert():
    """Baseline must not drift down during a sustained outage."""
    engine = DegradationEngine()
    feed(engine, pid=10, speeds=[1000]*15)   # build baseline ~1000
    baseline_before = engine.get_state(10).ewma_kbps

    feed(engine, pid=10, speeds=[10]*60)     # 60s outage
    baseline_after = engine.get_state(10).ewma_kbps

    assert baseline_after > 500, \
        f"FAIL — baseline drifted to {baseline_after:.0f} during outage (should stay near {baseline_before:.0f})"
    print(f"PASS — baseline stayed at {baseline_after:.0f} kbps during outage (was {baseline_before:.0f})")

# ── Run all tests ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\nRunning degradation engine tests...\n" + "─"*50)
    test_no_false_alert_during_warmup()
    test_healthy_flow_never_alerts()
    test_transient_blip_ignored()
    test_sustained_drop_fires_alert()
    test_alert_fires_at_correct_second()
    test_recovery_resets_counter()
    test_gaming_faster_gate()
    test_severity_increases_with_drop()
    test_baseline_freezes_during_alert()
    print("─"*50)
    print("All tests passed.\n")