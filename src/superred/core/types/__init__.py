"""Shared types used across all superred interfaces."""

from superred.core.types.budget import BudgetEstimate, BudgetUsage, HierarchicalBudget
from superred.core.types.context import (
    ActionRecord,
    ContextSnapshot,
    ObservationRecord,
    TurnResult,
)
from superred.core.types.controllable import (
    Controllable,
    ControllableSpec,
    ControllableValue,
    Modifier,
)
from superred.core.types.feedback import EvaluationResult, FeedbackResult, Score
from superred.core.types.observable import ObservableSpec, StaticObservable
from superred.core.types.security_claims import ClaimVerdict, OracleEvidence
from superred.core.types.task import TaskDefinition, TaskFeedback
from superred.core.types.threat_model import (
    Budget,
    InterfaceRole,
    InterfaceSpec,
    PropertyKind,
    RuntimeParamSpec,
    SecurityDomain,
    TargetMetadata,
    ThreatModel,
)
from superred.core.types.trajectory import Artifact, EventKind, TraceEvent

__all__ = [
    # Budget
    "BudgetEstimate",
    "BudgetUsage",
    "HierarchicalBudget",
    # Context
    "ActionRecord",
    "ContextSnapshot",
    "ObservationRecord",
    "TurnResult",
    # Controllable
    "Controllable",
    "ControllableSpec",
    "ControllableValue",
    "Modifier",
    # Feedback
    "EvaluationResult",
    "FeedbackResult",
    "Score",
    # Observable
    "ObservableSpec",
    "StaticObservable",
    # Security claims
    "ClaimVerdict",
    "OracleEvidence",
    # Task
    "TaskDefinition",
    "TaskFeedback",
    # Threat model
    "Budget",
    "InterfaceRole",
    "InterfaceSpec",
    "PropertyKind",
    "RuntimeParamSpec",
    "SecurityDomain",
    "TargetMetadata",
    "ThreatModel",
    # Trajectory
    "Artifact",
    "EventKind",
    "TraceEvent",
]
