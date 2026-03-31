"""superred — A modular framework for comprehensive red-teaming of AI systems."""

__version__ = "0.1.0"

from superred.interfaces import Target, Task, Optimizer, Judge, SecurityClaim, NotApplicable
from superred.types import (
    Event, EventResponse, Goal, Trajectory, SecurityDomainTag, ThreatModel,
    ControllableSpec, Controllable, Observable, ObservableValue,
    EvaluationResult, Score, OracleBundle,
)
