import threading
import time
import asyncio
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

# Import your existing logic and shared state!
from behavioral_classifier import (
    poll_process_io, dns_resolver, snapshot_and_detect,
    display_rows, recent_rootcauses, collector, lock, init_csv
)

app = FastAPI(title="Network Monitor Daemon")

# --- 1. Start the Background Threads Headlessly ---
@app.on_event("startup")
def startup_event():
    print("Starting background engines...")
    init_csv()
    threading.Thread(target=poll_process_io, daemon=True).start()
    threading.Thread(target=dns_resolver, daemon=True).start()
    threading.Thread(target=snapshot_and_detect, daemon=True).start()
    collector.start()
    print("Engines running in background.")

# --- 2. Serve the Frontend HTML ---
@app.get("/")
async def get_dashboard():
    with open("index.html", "r") as f:
        return HTMLResponse(f.read())

# --- 3. The WebSocket Data Stream ---
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Safely grab the current state from your classifier
            with lock:
                rows = list(display_rows)
                causes = [
                    {
                        "app": rc.alert.app_class,
                        "kbps": rc.alert.current_kbps,
                        "severity": rc.alert.severity,
                        "cause": rc.cause,
                        "confidence": rc.confidence,
                        "recommendation": rc.recommendation
                    } for rc in list(recent_rootcauses)[:3]
                ]
            
            snap = collector.snapshot
            
            # Package it all into a JSON payload
            payload = {
                "flows": rows,
                "root_causes": causes,
                "signals": {
                    "rtt": snap.rtt_ms,
                    "wifi": snap.wifi_signal_pct,
                    "cpu": snap.cpu_pct
                }
            }
            
            # Send to the browser
            await websocket.send_json(payload)
            await asyncio.sleep(1) # Send updates every second
            
    except WebSocketDisconnect:
        print("Client disconnected cleanly (tab closed).")
    except OSError as e:
        # This catches WinError 121 gracefully!
        print(f"OS network timeout (Browser lost connection to daemon): {e}")
    except Exception as e:
        # Catch-all to prevent the daemon from crashing on other weird network events
        print(f"Unexpected WebSocket error: {e}")

if __name__ == "__main__":
    # Run the server on port 8000
    uvicorn.run("web_daemon:app", host="127.0.0.1", port=8000, log_level="info")