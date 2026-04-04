from degradation_engine import Alert
from signal_collector import SignalSnapshot
from root_cause_engine import RootCauseEngine

# 1. Start the engine
engine = RootCauseEngine()

# 2. Create a fake Alert (Simulating a 95% speed drop on YouTube)
fake_alert = Alert(
    pid=9999,
    proc="chrome.exe",
    app_class="Video Streaming",
    severity=95,
    current_kbps=50.0,
    baseline_kbps=5000.0,
    degraded_secs=10,
    reason="Speed dropped 95% below normal"
)

# 3. Create fake Signals (Simulating terrible Wi-Fi)
fake_signals = SignalSnapshot(
    rtt_ms=250.0,
    retransmit_high=True,
    retransmit_rate=15.0,
    wifi_weak=True,
    wifi_signal_pct=25
)

# 4. Run it!
print("Feeding terrible network data to the engine...")
result = engine.analyse(fake_alert, fake_signals)

print(f"Diagnosis: {result.cause}")
print(f"Fix: {result.recommendation}")
print("\nSUCCESS! Check your folder for root_cause_log.csv!")