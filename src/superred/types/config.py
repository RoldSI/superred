# src/superred/types/config.py
from __future__ import annotations
from dataclasses import dataclass
from superred.types.security import SecurityDomainTag

@dataclass(frozen=True)
class ConfigSpec:
    name: str
    security_domain: SecurityDomainTag
    description: str

@dataclass(frozen=True)
class StateSpec:
    name: str
    description: str

@dataclass(frozen=True)
class RuntimeParamSpec:
    name: str
    description: str
