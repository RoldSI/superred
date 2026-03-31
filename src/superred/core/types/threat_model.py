"""Threat model as a budgeted access profile over tagged interfaces.

A threat model M = (C, O, F, B) defines which controllables, observables, and
feedback channels are exposed to the optimizer, plus budget constraints. Each
interface item is tagged with security domain labels drawn from a vocabulary.

The classical black/grey/white-box taxonomy is a special case: black-box
restricts C to user surfaces with minimal O and F; white-box exposes everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SecurityDomain(str, Enum):
    """Default security domain vocabulary.

    These tags annotate every controllable, observable, and feedback interface
    to indicate which security boundary it belongs to. Target modules may extend
    this with custom string tags.
    """

    USER = "user"
    EXTERNAL_DATA = "external_data"
    TOOL_CATALOG = "tool_catalog"
    INTERNAL_CONTEXT = "internal_context"
    MEMORY = "memory"
    MODEL = "model"
    VERIFIER = "verifier"
    CODE = "code"
    CUSTOM = "custom"


class InterfaceRole(str, Enum):
    """Role of an interface in the threat model."""

    CONTROLLABLE = "controllable"
    OBSERVABLE = "observable"
    FEEDBACK = "feedback"


class PropertyKind(str, Enum):
    """Primitive security property families from the contextual agent security
    framework.  Attack classes (indirect prompt injection, jailbreak, task
    drift, ...) are violations of one or more of these families, not primitive
    claim types themselves."""

    TASK_ALIGNMENT = "task_alignment"
    ACTION_ALIGNMENT = "action_alignment"
    AUTHORIZED_INSTRUCTION_FOLLOWING = "authorized_instruction_following"
    DATA_ISOLATION = "data_isolation"


@dataclass(frozen=True)
class InterfaceSpec:
    """Specification of a single interface point (controllable, observable,
    or feedback channel) in the target system."""

    name: str
    role: InterfaceRole
    domains: frozenset[SecurityDomain | str]
    description: str
    schema: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeParamSpec:
    """Specification of a runtime parameter required by a target module."""

    name: str
    description: str
    required: bool
    secret: bool = False
    default: Any = None


@dataclass(frozen=True)
class TargetMetadata:
    """Descriptive metadata for a target module."""

    target_id: str
    display_name: str
    description: str
    version: str
    observability_tier: str
    supports_parallel_runs: bool = False


@dataclass(frozen=True)
class Budget:
    """Resource constraints for an optimization / evaluation run.
    All fields are optional — ``None`` means unlimited."""

    max_iterations: int | None = None
    max_model_calls: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    max_wall_clock_seconds: float | None = None
    max_cost_usd: float | None = None


@dataclass(frozen=True)
class ThreatModel:
    """A budgeted access profile defining what the optimizer may access.

    The controller builds threat models by selecting subsets of the target's
    full interface set.  The optimizer receives only what the threat model
    exposes.

    Attributes:
        allowed_controllables: Interface names exposed as controllables.
        allowed_observables: Interface names exposed as observables.
        allowed_feedback: Interface names exposed as feedback channels.
        budget: Resource constraints for the evaluation.
    """

    allowed_controllables: frozenset[str]
    allowed_observables: frozenset[str]
    allowed_feedback: frozenset[str]
    budget: Budget
