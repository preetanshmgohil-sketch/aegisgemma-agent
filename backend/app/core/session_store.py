"""In-memory audit session store (SQLite-backed persistence is optional)."""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..schemas.audit_schema import AuditReport


@dataclass
class AuditSession:
    id: str
    target: str
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    report: AuditReport | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    subscribers: list[asyncio.Queue] = field(default_factory=list)
    task: asyncio.Task | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "event_count": len(self.events),
            "report": self.report.model_dump() if self.report else None,
        }


class SessionStore:
    """Keeps audit sessions and fans out streaming events."""

    def __init__(self) -> None:
        self._sessions: dict[str, AuditSession] = {}
        self._lock = asyncio.Lock()

    async def create(self, target: str) -> AuditSession:
        async with self._lock:
            session = AuditSession(id=uuid.uuid4().hex[:12], target=target)
            self._sessions[session.id] = session
            return session

    async def get(self, session_id: str) -> AuditSession | None:
        async with self._lock:
            return self._sessions.get(session_id)

    async def list(self) -> list[dict[str, Any]]:
        async with self._lock:
            return [s.snapshot() for s in sorted(self._sessions.values(), key=lambda s: -s.created_at)]

    async def publish(self, session: AuditSession, event: dict[str, Any]) -> None:
        session.events.append(event)
        for queue in list(session.subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def subscribe(self, session: AuditSession) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=512)
        session.subscribers.append(queue)
        return queue

    async def unsubscribe(self, session: AuditSession, queue: asyncio.Queue) -> None:
        if queue in session.subscribers:
            session.subscribers.remove(queue)
