"""FastAPI layer: REST for the analyst console + a WebSocket that pushes live incident/action updates."""
from __future__ import annotations
import asyncio, threading
from pathlib import Path
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sentinel.container import Container

STATIC = Path(__file__).parent / "static"


class AnalystBody(BaseModel):
    analyst: str = "analyst1"
    reason: str = ""


class WebSocketHub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept(); self._loop = asyncio.get_running_loop(); self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    def listener(self, topic: str):
        def handle(msg) -> None:                       # called from the pipeline thread
            if self._loop is None or not self._clients:
                return
            data = msg.model_dump(mode="json") if isinstance(msg, BaseModel) else msg
            asyncio.run_coroutine_threadsafe(self._broadcast({"topic": topic, "data": data}), self._loop)
        return handle

    async def _broadcast(self, payload: dict) -> None:
        for ws in list(self._clients):
            try:
                await ws.send_json(payload)
            except Exception:
                self._clients.discard(ws)


def create_app(container: Container | None = None) -> FastAPI:
    c, hub, lock = container or Container(), WebSocketHub(), threading.RLock()
    c.add_hook(lambda ct: [ct.bus.subscribe(t, hub.listener(t)) for t in ("incidents", "actions")])
    app = FastAPI(title="SENTINEL analyst API")
    dump = lambda m: m.model_dump(mode="json")

    def decision_time(rec) -> float:
        # simulated clock: the analyst reacts `analyst_approval_delay_s` after the action was proposed
        return max(c.clock.now, rec.proposed_at) + c.settings.analyst_approval_delay_s

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.post("/api/simulate/{scenario}")
    def simulate(scenario: str):
        if scenario not in {"both", "phishing", "lateral", "benign"}:
            raise HTTPException(404, "unknown scenario")
        with lock:
            c.reset()
            n = c.run_scenario(scenario)
            return {"events": n, "incidents": len(c.correlator.incidents()), "pending": len(c.orchestrator.pending())}

    @app.get("/api/incidents")
    def incidents():
        with lock:
            out = []
            for inc in sorted(c.correlator.incidents(), key=lambda i: i.first_ts):
                rep = c.reports.get(inc.id)
                out.append({"incident": dump(inc), "report": dump(rep) if rep else None,
                            "actions": [dump(a) for a in c.actions.all() if a.incident_id == inc.id]})
            return out

    @app.get("/api/approvals")
    def approvals():
        return [dump(a) for a in c.orchestrator.pending()]

    def _act(fn_name: str, action_id: str, body: AnalystBody):
        with lock:
            rec = c.actions.get(action_id)
            if rec is None:
                raise HTTPException(404, "unknown action")
            try:
                fn = getattr(c.orchestrator, fn_name)
                args = (action_id, body.analyst, decision_time(rec))
                return dump(fn(*args, body.reason) if fn_name == "reject" else fn(*args))
            except ValueError as exc:
                raise HTTPException(409, str(exc))

    @app.post("/api/actions/{action_id}/approve")
    def approve(action_id: str, body: AnalystBody = AnalystBody()):
        return _act("approve", action_id, body)

    @app.post("/api/actions/{action_id}/reject")
    def reject(action_id: str, body: AnalystBody = AnalystBody()):
        return _act("reject", action_id, body)

    @app.post("/api/actions/{action_id}/rollback")
    def rollback(action_id: str, body: AnalystBody = AnalystBody()):
        return _act("rollback", action_id, body)

    @app.get("/api/audit")
    def audit(limit: int = 50):
        return [dump(r) for r in c.audit.all(limit)]

    @app.get("/api/audit/verify")
    def verify():
        ok, bad = c.audit.verify()
        return {"valid": ok, "broken_at": bad}

    @app.get("/api/metrics")
    def metrics():
        with lock:
            return c.evaluate()

    @app.websocket("/ws")
    async def ws(socket: WebSocket):
        await hub.connect(socket)
        try:
            while True:
                await socket.receive_text()
        except WebSocketDisconnect:
            hub.disconnect(socket)

    return app


def get_app() -> FastAPI:        # uvicorn sentinel.api.app:get_app --factory
    return create_app()
