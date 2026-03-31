# tests/test_types/test_init.py
def test_types_reexports():
    """All core types importable from superred.types."""
    from superred.types import (
        # security.py
        SecurityDomainTag, SecurityDomain, ThreatModel, Budget,
        # event.py
        Event, EventResponse, ControllablePreCallEvent, ControllablePostCallEvent,
        ControllableInjection, PassThrough, OptimizerDoneEvent,
        # controllable.py
        ControllableSpec, Controllable, RequestAnswerPair,
        # observable.py
        Observable, ObservableValue,
        # goal.py
        Goal,
        # config.py
        ConfigSpec, StateSpec, RuntimeParamSpec,
        # feedback.py
        Score, EvaluationResult, FeedbackResult,
        # trajectory.py
        Trajectory, TrajectoryEntry, TrajectoryEntryType,
        MODEL_REQUEST, MODEL_RESPONSE, TOOL_CALL, TOOL_RESULT, INJECTION, FEEDBACK,
        # budget.py
        BudgetUsage, HierarchicalBudget,
        # claim.py
        PropertyKind, ClaimVerdict, OracleEvidence, ContextSnapshot, OracleBundle,
    )
