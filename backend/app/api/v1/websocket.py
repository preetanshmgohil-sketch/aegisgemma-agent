"""WebSocket endpoint streaming live audit progress."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ...core.session_store import SessionStore

router = APIRouter(tags=["stream"])


@router.websocket("/api/v1/audits/{session_id}/stream")
async def stream_audit(websocket: WebSocket, session_id: str) -> None:
    await websocket.accept()
    store: SessionStore = websocket.app.state.store

    session = await store.get(session_id)
    if session is None:
        await websocket.send_json({"kind": "error", "message": "Audit session not found"})
        await websocket.close(code=4404)
        return

    queue = await store.subscribe(session)
    sent = 0
    try:
        # `session.events` is the single source of truth (append-only). The
        # queue is only a wake-up signal, so a subscriber can never miss an
        # event that lands between the replay and the live stream, and never
        # receives the same event twice.
        while True:
            events = session.events
            while sent < len(events):
                event = events[sent]
                sent += 1
                await websocket.send_json(event)
                if event.get("kind") in {"complete", "error"}:
                    await websocket.close()
                    return

            try:
                await asyncio.wait_for(queue.get(), timeout=25.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"kind": "heartbeat"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await store.unsubscribe(session, queue)
        try:
            await websocket.close()
        except RuntimeError:
            pass
