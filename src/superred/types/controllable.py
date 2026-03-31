# src/superred/types/controllable.py
from __future__ import annotations
from dataclasses import dataclass, field
from superred.types.security import SecurityDomainTag

@dataclass(frozen=True)
class ControllableSpec:
    name: str
    security_domain: SecurityDomainTag
    description: str = ""
    value_type: str = "text"
    required: bool = False

@dataclass(frozen=True)
class RequestAnswerPair:
    request: str
    answer: str

@dataclass
class Controllable:
    spec: ControllableSpec
    history: list[RequestAnswerPair] = field(default_factory=list)
