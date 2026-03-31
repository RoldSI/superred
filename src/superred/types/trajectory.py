# src/superred/types/trajectory.py
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from superred.types.feedback import FeedbackResult
from superred.types.security import SecurityDomainTag


@dataclass(frozen=True)
class TrajectoryEntryType:
    name: str
    actor: str
    content_type: type


MODEL_REQUEST = TrajectoryEntryType("model_request", "target", str)
MODEL_RESPONSE = TrajectoryEntryType("model_response", "llm", str)
TOOL_CALL = TrajectoryEntryType("tool_call", "target", str)
TOOL_RESULT = TrajectoryEntryType("tool_result", "tool", str)
INJECTION = TrajectoryEntryType("injection", "optimizer", str)
FEEDBACK = TrajectoryEntryType("feedback", "evaluator", FeedbackResult)


@dataclass
class TrajectoryEntry:
    entry_type: TrajectoryEntryType
    content: Any
    timestamp: datetime = field(default_factory=datetime.now)
    security_domain: SecurityDomainTag | None = None
    parent_id: str | None = None


class Trajectory:
    """Async-safe, append-only trajectory stream."""

    def __init__(self) -> None:
        self._entries: list[TrajectoryEntry] = []
        self._cursor: int = 0
        self._closed: bool = False
        self._lock: asyncio.Lock = asyncio.Lock()

    async def emit(self, entry: TrajectoryEntry) -> None:
        async with self._lock:
            if self._closed:
                raise RuntimeError("Cannot emit to a closed trajectory")
            self._entries.append(entry)

    def close(self) -> None:
        self._closed = True

    def snapshot(self) -> list[TrajectoryEntry]:
        return list(self._entries)

    async def drain(self) -> list[TrajectoryEntry]:
        async with self._lock:
            new = self._entries[self._cursor:]
            self._cursor = len(self._entries)
            return new

    def __len__(self) -> int:
        return len(self._entries)

    @classmethod
    def from_replay(cls, entries: list[TrajectoryEntry], replay_until: int) -> Trajectory:
        t = cls()
        t._entries = list(entries[:replay_until])
        t._cursor = 0
        return t
