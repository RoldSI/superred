"""Core interfaces and types for the superred framework."""

from superred.core.interfaces import (
    OptimizerInterface,
    TargetModuleInterface,
    TaskModuleInterface,
)
from superred.core.types import (
    Artifact,
    Budget,
    BudgetEstimate,
    BudgetUsage,
    Controllable,
    ControllableSpec,
    ControllableValue,
    CostRecord,
    EvaluationResult,
    FeedbackResult,
    Modifier,
    ObservableSpec,
    OperationType,
    Score,
    SecurityDomain,
    SecurityTag,
    StaticObservable,
    ThreatModel,
    TraceEvent,
    Trajectory,
)

__all__ = [
    # Interfaces
    "OptimizerInterface",
    "TargetModuleInterface",
    "TaskModuleInterface",
    # Types
    "Artifact",
    "Budget",
    "BudgetEstimate",
    "BudgetUsage",
    "Controllable",
    "ControllableSpec",
    "ControllableValue",
    "CostRecord",
    "EvaluationResult",
    "FeedbackResult",
    "Modifier",
    "ObservableSpec",
    "OperationType",
    "Score",
    "SecurityDomain",
    "SecurityTag",
    "StaticObservable",
    "ThreatModel",
    "TraceEvent",
    "Trajectory",
]
