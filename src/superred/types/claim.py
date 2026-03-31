# src/superred/types/claim.py
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable

from superred.types.goal import Goal

if TYPE_CHECKING:
    from superred.types.trajectory import TrajectoryEntry


class PropertyKind(Enum):
    TASK_ALIGNMENT = "task_alignment"
    ACTION_ALIGNMENT = "action_alignment"
    AUTHORIZED_INSTRUCTION_FOLLOWING = "authorized_instruction_following"
    DATA_ISOLATION = "data_isolation"


@dataclass(frozen=True)
class OracleEvidence:
    name: str
    value: str
    confidence: float
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ClaimVerdict:
    property_kind: PropertyKind
    satisfied: bool
    confidence: float
    evidence: list[OracleEvidence]
    explanation: str


@dataclass(frozen=True)
class ContextSnapshot:
    goal: Goal
    trajectory_entries: list[TrajectoryEntry]
    task_config: dict[str, str]


@dataclass(frozen=True)
class OracleBundle:
    ground_truth_output: str | None = None
    forbidden_actions: list[str] = field(default_factory=list)
    sensitive_data: dict[str, str] = field(default_factory=dict)
    source_attribution: dict[str, str] = field(default_factory=dict)


ClaimPredicate = Callable[[ContextSnapshot, OracleBundle], ClaimVerdict]
