"""superred — A modular framework for comprehensive red-teaming of AI systems."""

__version__ = "0.1.0"

from superred.interfaces import Target, Task, Optimizer, Judge, SecurityClaim, NotApplicable
from superred.types import (
    Event, EventResponse, Goal, Trajectory, SecurityDomainTag, ThreatModel,
    Budget, ControllableSpec, Controllable, Observable, ObservableValue,
    EvaluationResult, Score, OracleBundle, HierarchicalBudget, PropertyKind,
    ClaimVerdict,
)

__all__ = [
    "__version__",
    # interfaces
    "Target",
    "Task",
    "Optimizer",
    "Judge",
    "SecurityClaim",
    "NotApplicable",
    # types
    "Event",
    "EventResponse",
    "Goal",
    "Trajectory",
    "SecurityDomainTag",
    "ThreatModel",
    "Budget",
    "ControllableSpec",
    "Controllable",
    "Observable",
    "ObservableValue",
    "EvaluationResult",
    "Score",
    "OracleBundle",
    "HierarchicalBudget",
    "PropertyKind",
    "ClaimVerdict",
]
