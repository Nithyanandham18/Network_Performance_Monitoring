import threading
import time
import os

# Import your existing engines and sniffers!
from behavioral_classifier import (
    update_process_mapping, start_sniffer, 
    port_to_process, port_history, current_bytes, classify_behavior
)
from degradation_engine import DegradationEngine
from signal_collector import SignalCollector
from root_cause_engine import RootCauseEngine

def clear_screen():
    """Clears the console screen for a clean UI."""
    os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    print("Starting Console Monitor... (Initializing Network Hooks)")
    
    # 1. Initialize the Engines
    engine = DegradationEngine()
    collector = SignalCollector(target_ip="8.8.8.8")
    rc_engine = RootCauseEngine()

    # 2. Start the Background Threads
    threading.Thread(target=update_process_mapping, daemon=True).start()
    threading.Thread(target=start_sniffer, daemon=True).start()
    collector.start()
    
    # Give Npcap a second to warm up
    time.sleep(2) 
    
    # Keep track of recent alerts to display at the bottom of the screen
    recent_alerts = []

    try:
        while True:
            # Move current bytes into history array for the math engines
            for port in list(port_to_process.keys()):
                port_history[port].append(current_bytes.get(port, 0))
            current_bytes.clear()

            # Prepare the UI
            clear_screen()
            print("=== NETWORK PERFORMANCE MONITOR (CONSOLE MODE) ===")
            print(f"{'Port':<8} | {'Process':<15} | {'Speed':<12} | {'Classification'}")
            print("-" * 60)

            # Evaluate all active flows
            for port, process_name in list(port_to_process.items()):
                history = list(port_history[port])
                
                # Only show flows that are actually moving data right now
                if sum(history) > 0:
                    recent_kbps = (history[-1] * 8) / 1000
                    classification = classify_behavior(process_name, history)
                    
                    # Print standard flow to the table
                    print(f"{port:<8} | {process_name:<15} | {recent_kbps:>6.0f} kbps | {classification}")
                    
                    # Feed the engine to check for drops
                    alert = engine.update(pid=port, proc=process_name, classification=classification, current_kbps=recent_kbps)
                    
                    # If an alert fires, run the Root Cause Analysis!
                    if alert:
                        snap = collector.snapshot
                        diagnosis = rc_engine.analyse(alert, snap)
                        
                        time_now = time.strftime("%H:%M:%S")
                        alert_msg = (
                            f"\n[{time_now}] 🚨 ALERT: {alert.reason}\n"
                            f"   -> Cause: {diagnosis.cause} ({diagnosis.confidence}% confidence)\n"
                            f"   -> Fix:   {diagnosis.recommendation}"
                        )
                        recent_alerts.append(alert_msg)

            # Print recent alerts at the bottom of the screen
            if recent_alerts:
                print("\n" + "=" * 60)
                print(" ⚠️ RECENT DEGRADATION ALERTS")
                print("=" * 60)
                # Show only the 3 most recent alerts so it doesn't flood the screen
                for a in recent_alerts[-3:]:
                    print(a)

            # Wait 1 second before refreshing the screen
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nMonitor stopped safely by user.")