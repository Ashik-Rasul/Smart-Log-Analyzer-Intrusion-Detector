import os
import json
import asyncio
import threading
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from core.logger import setup_logger

logger = setup_logger(__name__)

app = FastAPI(title="Owl Monitor API", version="1.0")

# ── WebSocket Connection Manager ──────────────────────────────────────────────

class ConnectionManager:
    """Manages all active WebSocket connections from browser clients."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Send a JSON message to every connected browser."""
        data = json.dumps(message)
        with self._lock:
            connections = list(self.active_connections)
        for connection in connections:
            try:
                await connection.send_text(data)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# ── In-memory store for recent events and metrics ─────────────────────────────

_store = {
    "alerts": [],           # List of recent alert dicts (max 100)
    "events": [],           # List of recent normalized events (max 200)
    "blocked_ips": [],      # List of currently blocked IPs
    "fim_violations": [],   # List of FIM violation events
    "metrics": {
        "threat_level": "Low",
        "active_alerts": 0,
        "network_events": 0,
        "system_status": "Healthy",
    }
}
_store_lock = threading.Lock()

def push_alert(alert_data: dict):
    """Called from the EventBus thread to store an alert and schedule a broadcast."""
    with _store_lock:
        _store["alerts"].insert(0, alert_data)
        if len(_store["alerts"]) > 100:
            _store["alerts"] = _store["alerts"][:100]
        _store["metrics"]["active_alerts"] = len(_store["alerts"])
        
        # Update threat level based on the highest severity we've seen recently
        levels = {"Low": 0, "Medium": 1, "High": 2, "Very High": 3, "Critical": 4}
        current_level = levels.get(_store["metrics"]["threat_level"], 0)
        new_level = levels.get(alert_data.get("level", "Low"), 0)
        if new_level > current_level:
            for name, val in levels.items():
                if val == new_level:
                    _store["metrics"]["threat_level"] = name
                    break

    # Schedule the async broadcast from the sync thread
    _schedule_broadcast({"type": "new_alert", "data": alert_data})

def push_event(event_data: dict):
    """Called from EventBus thread to store a normalized event."""
    with _store_lock:
        _store["events"].insert(0, event_data)
        if len(_store["events"]) > 200:
            _store["events"] = _store["events"][:200]
        _store["metrics"]["network_events"] = len(_store["events"])
    
    _schedule_broadcast({"type": "new_event", "data": event_data})

def push_blocked_ip(ip: str):
    """Called when an IP gets blocked via iptables."""
    with _store_lock:
        if ip not in _store["blocked_ips"]:
            _store["blocked_ips"].append(ip)
    _schedule_broadcast({"type": "ip_blocked", "data": {"ip": ip}})

def get_store():
    """Return a snapshot of the current state for initial page load."""
    with _store_lock:
        return json.loads(json.dumps(_store))

# ── Async bridge: schedule broadcasts from sync threads ───────────────────────

_loop = None

def set_event_loop(loop):
    global _loop
    _loop = loop

def _schedule_broadcast(message: dict):
    """Safely schedule an async broadcast from any thread."""
    if _loop and _loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast(message), _loop)

# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/api/state")
async def get_state():
    """Return the full current state for initial page load."""
    return get_store()

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; we only push data server → client
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ── Mount Static Files (the web-ui directory) ─────────────────────────────────

web_ui_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web-ui")

@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(web_ui_dir, "index.html"))

app.mount("/", StaticFiles(directory=web_ui_dir), name="static")

# ── Server Runner ─────────────────────────────────────────────────────────────

def start_server(host="0.0.0.0", port=8000):
    """Start the Uvicorn server in a background daemon thread."""
    import uvicorn

    loop = asyncio.new_event_loop()
    set_event_loop(loop)
    
    config = uvicorn.Config(app, host=host, port=port, loop="asyncio", log_level="warning")
    server = uvicorn.Server(config)
    
    def _run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.serve())
    
    thread = threading.Thread(target=_run, daemon=True, name="uvicorn-server")
    thread.start()
    logger.info(f"Web Dashboard started at http://{host}:{port}")
    return thread
