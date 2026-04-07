import asyncio
import behavioral_classifier as bc
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(prefix="/ws", tags=["websocket"])

@router.websocket("")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Safely grab the current state from the classifier module
            with bc.lock:
                rows = list(bc.display_rows)
                causes = [
                    {
                        "app": rc.alert.app_class,
                        "kbps": rc.alert.current_kbps,
                        "severity": rc.alert.severity,
                        "cause": rc.cause,
                        "confidence": rc.confidence,
                        "recommendation": rc.recommendation
                    } for rc in list(bc.recent_rootcauses)[:3]
                ]

            snap = bc.collector.snapshot

            payload = {
                "flows": rows,
                "root_causes": causes,
                "signals": {
                    "rtt": snap.rtt_ms,
                    "wifi": snap.wifi_signal_pct,
                    "cpu": snap.cpu_pct
                }
            }

            await websocket.send_json(payload)
            await asyncio.sleep(1)

    except WebSocketDisconnect:
        print("Client disconnected cleanly (tab closed).")
    except OSError as e:
        print(f"OS network timeout: {e}")
    except Exception as e:
        print(f"Unexpected WebSocket error: {e}")
