"""
main.py — NetPulse FastAPI backend with SQLite database integration
"""
import asyncio
import threading
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

import behavioral_classifier as bc
from behavioral_classifier import poll_process_io, dns_resolver, snapshot_and_detect, init_csv
from database import init_db, db_write_signal_snapshot
from api.routers import history

# ── DB snapshot writer (every 30s) ──────────────────────────────────────────

def _signal_snapshot_writer():
    """Background thread: persist a signal snapshot to the DB every 30 seconds."""
    while True:
        time.sleep(30)
        try:
            snap = bc.collector.snapshot
            with bc.lock:
                rows = list(bc.display_rows)
            total_kbps = sum(r.get("kbps", 0) for r in rows)
            peak_kbps  = max((r.get("kbps", 0) for r in rows), default=0)
            db_write_signal_snapshot(snap, total_kbps, peak_kbps, len(rows))
        except Exception as e:
            print(f"[DB] snapshot writer error: {e}")


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Initializing SQLite database...")
    init_db()
    init_csv()
    print("Starting background engines...")
    threading.Thread(target=poll_process_io,      daemon=True).start()
    threading.Thread(target=dns_resolver,          daemon=True).start()
    threading.Thread(target=snapshot_and_detect,   daemon=True).start()
    threading.Thread(target=_signal_snapshot_writer, daemon=True).start()
    bc.collector.start()
    print("All engines running.")
    yield
    print("Shutdown complete.")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="NetPulse — Network Monitor API",
    description="AI-powered network monitoring with real-time classification, degradation detection, and SQL persistence.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(history.router)

# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            with bc.lock:
                rows   = list(bc.display_rows)
                causes = [
                    {
                        "app":            rc.alert.app_class,
                        "kbps":           rc.alert.current_kbps,
                        "severity":       rc.alert.severity,
                        "cause":          rc.cause,
                        "confidence":     rc.confidence,
                        "recommendation": rc.recommendation,
                    }
                    for rc in list(bc.recent_rootcauses)[:3]
                ]
            snap = bc.collector.snapshot
            await websocket.send_json({
                "flows":       rows,
                "root_causes": causes,
                "signals": {
                    "rtt":  snap.rtt_ms,
                    "wifi": snap.wifi_signal_pct,
                    "cpu":  snap.cpu_pct,
                },
            })
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        print("Client disconnected.")
    except OSError as e:
        print(f"WS OS error: {e}")
    except Exception as e:
        print(f"WS error: {e}")


# ── Frontend ──────────────────────────────────────────────────────────────────

@app.get("/", summary="Dashboard UI", tags=["frontend"])
async def get_dashboard():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse(
            "<h1>NetPulse Backend Running</h1>"
            "<p>Place <code>index.html</code> next to <code>main.py</code> to serve the dashboard.</p>"
            "<p>API docs: <a href='/docs'>/docs</a></p>"
        )


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, log_level="info")
