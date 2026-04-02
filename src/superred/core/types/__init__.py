"""Shared types used across all superred interfaces."""

from superred.core.types.controllable import (
    Controllable,
    ControllableSpec,
    RequestAnswerPair,
)
from superred.core.types.evaluation import EvaluationResult, FeedbackResult, Score
from superred.core.types.event import (
    ControllableInjection,
    ControllablePostCallEvent,
    ControllablePreCallEvent,
    Event,
    EventResponse,
    NoModification,
    RunEndEvent,
    RunEndResponse,
    RunStartEvent,
)
from superred.core.types.goal import Goal
from superred.core.types.observable import Observable, ObservableValue
from superred.core.types.security_domain import SecurityDomain, SecurityDomainTag
from superred.core.types.state import ConfigSpec, QueryParam, QuerySpec
from superred.core.types.trajectory import (
    FEEDBACK,
    MODEL_REQUEST,
    MODEL_RESPONSE,
    FilteredTrajectory,
    ReadableTrajectory,
    Trajectory,
    TrajectoryEntry,
    TrajectoryEntryType,
)

__all__ = [
    "ConfigSpec",
    "Controllable",
    "ControllableInjection",
    "ControllablePostCallEvent",
    "ControllablePreCallEvent",
    "ControllableSpec",
    "EvaluationResult",
    "Event",
    "EventResponse",
    "FEEDBACK",
    "FeedbackResult",
    "FilteredTrajectory",
    "Goal",
    "MODEL_REQUEST",
    "MODEL_RESPONSE",
    "NoModification",
    "Observable",
    "ObservableValue",
    "QueryParam",
    "QuerySpec",
    "RequestAnswerPair",
    "RunEndEvent",
    "RunEndResponse",
    "RunStartEvent",
    "Score",
    "SecurityDomain",
    "SecurityDomainTag",
    "ReadableTrajectory",
    "Trajectory",
    "TrajectoryEntry",
    "TrajectoryEntryType",
]
