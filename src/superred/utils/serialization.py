"""JSON serialisation helpers."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class SuperredEncoder(json.JSONEncoder):
    """JSON encoder that handles dataclasses, datetimes, enums, frozensets."""

    def default(self, o: Any) -> Any:
        if is_dataclass(o) and not isinstance(o, type):
            return asdict(o)
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, Enum):
            return o.value
        if isinstance(o, frozenset):
            return sorted(o)
        if isinstance(o, set):
            return sorted(o)
        return super().default(o)


def to_json(obj: Any, indent: int = 2) -> str:
    """Serialise any object to JSON string."""
    return json.dumps(obj, cls=SuperredEncoder, indent=indent)


def save_json(obj: Any, path: str, indent: int = 2) -> None:
    """Save object as JSON file."""
    with open(path, "w") as f:
        json.dump(obj, f, cls=SuperredEncoder, indent=indent)
