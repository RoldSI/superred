# src/superred/types/observable.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from superred.types.security import SecurityDomainTag

@dataclass(frozen=True)
class Observable:
    name: str
    security_domain: SecurityDomainTag
    description: str = ""
    observable_type: str = "text"

@dataclass(frozen=True)
class ObservableValue:
    observable: Observable
    content: Any = None
