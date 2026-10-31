"""WebSocket streaming tests — these cover the late-subscriber race."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from app.core.session_store import SessionStore
from app.main import app

BASE = "http://testserver"


class TestAuditEventStream:
    def _start_audit(self, client: TestClient, target: str) -> str:
        response = client.post(
            "/api/v1/audits",
            files={"files": ("v.py", b"os.system(cmd)\n", "text/x-python")},
            data={"target": target},
        )
        assert response.status_code == 202
        return response.json()["id"]

    def _drain(self, client: TestClient, session_id: str) -> list[dict]:
        received: list[dict] = []
        with client.websocket_connect(f"/api/v1/audits/{session_id}/stream") as socket:
            while True:
                event = socket.receive_json()
                received.append(event)
                if event.get("kind") in {"complete", "error"}:
                    break
        return received

    def test_stream_delivers_every_event_including_complete(self):
        with TestClient(app) as client:
            session_id = self._start_audit(client, "ws-target")
            received = self._drain(client, session_id)

        kinds = [e["kind"] for e in received]
        assert kinds.count("complete") == 1
        assert kinds[-1] == "complete"
        report = received[-1]["data"]["report"]
        assert report["findings"]
        assert report["risk_index"] > 0

    def test_late_subscriber_still_receives_the_complete_event(self):
        """Subscribing after the audit finished must not lose the terminal event."""
        with TestClient(app) as client:
            session_id = self._start_audit(client, "late")

            # Wait for the audit to finish before connecting.
            for _ in range(100):
                status = client.get(f"/api/v1/audits/{session_id}").json()["status"]
                if status in {"completed", "failed"}:
                    break
                import time

                time.sleep(0.1)

            received = self._drain(client, session_id)

        assert received[-1]["kind"] == "complete"
        assert received[-1]["data"]["report"]["findings"]

    def test_no_duplicate_events_are_delivered(self):
        with TestClient(app) as client:
            session_id = self._start_audit(client, "dupes")
            received = self._drain(client, session_id)

        signatures = [(e["kind"], e["stage"], e["message"]) for e in received]
        assert len(signatures) == len(set(signatures))


class TestSessionStore:
    @pytest.mark.asyncio
    async def test_publish_appends_to_event_log(self):
        store = SessionStore()
        session = await store.create("t")
        await store.publish(session, {"kind": "stage", "stage": "A", "message": "x"})
        await store.publish(session, {"kind": "complete", "stage": "B", "message": "y"})
        assert len(session.events) == 2
        assert session.events[-1]["kind"] == "complete"

    @pytest.mark.asyncio
    async def test_subscribers_receive_published_events(self):
        store = SessionStore()
        session = await store.create("t")
        queue = await store.subscribe(session)
        await store.publish(session, {"kind": "stage", "stage": "A", "message": "x"})
        event = await asyncio.wait_for(queue.get(), timeout=2)
        assert event["kind"] == "stage"

    @pytest.mark.asyncio
    async def test_unsubscribe_stops_delivery(self):
        store = SessionStore()
        session = await store.create("t")
        queue = await store.subscribe(session)
        await store.unsubscribe(session, queue)
        await store.publish(session, {"kind": "stage", "stage": "A", "message": "x"})
        assert queue.empty()
