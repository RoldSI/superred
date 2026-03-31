"""Tests for core type definitions."""

from superred.core.types.threat_model import (
    Budget,
    InterfaceRole,
    InterfaceSpec,
    PropertyKind,
    SecurityDomain,
    TargetMetadata,
    ThreatModel,
)
from superred.core.types.trajectory import EventKind, TraceEvent
from superred.core.types.context import (
    ActionRecord,
    ContextSnapshot,
    ObservationRecord,
    TurnResult,
)
from superred.core.types.security_claims import ClaimVerdict, OracleEvidence
from superred.core.types.task import TaskDefinition, TaskFeedback
from superred.core.types.budget import BudgetEstimate, BudgetUsage, HierarchicalBudget


def test_security_domain_is_string():
    assert SecurityDomain.USER == "user"
    assert SecurityDomain.EXTERNAL_DATA == "external_data"
    assert isinstance(SecurityDomain.MODEL.value, str)


def test_interface_role_values():
    assert InterfaceRole.CONTROLLABLE == "controllable"
    assert InterfaceRole.OBSERVABLE == "observable"
    assert InterfaceRole.FEEDBACK == "feedback"


def test_property_kind_values():
    assert PropertyKind.TASK_ALIGNMENT == "task_alignment"
    assert PropertyKind.DATA_ISOLATION == "data_isolation"
    assert len(PropertyKind) == 4


def test_interface_spec_frozen():
    spec = InterfaceSpec(
        name="user_query",
        role=InterfaceRole.CONTROLLABLE,
        domains=frozenset({SecurityDomain.USER}),
        description="The user's query",
    )
    assert spec.name == "user_query"
    assert SecurityDomain.USER in spec.domains


def test_target_metadata_frozen():
    meta = TargetMetadata(
        target_id="test",
        display_name="Test Target",
        description="A test target",
        version="1.0",
        observability_tier="proxy",
    )
    assert meta.target_id == "test"
    assert meta.supports_parallel_runs is False


def test_budget_defaults_to_none():
    b = Budget()
    assert b.max_iterations is None
    assert b.max_cost_usd is None


def test_threat_model_frozen():
    tm = ThreatModel(
        allowed_controllables=frozenset({"user_input"}),
        allowed_observables=frozenset({"final_output"}),
        allowed_feedback=frozenset({"attack_success"}),
        budget=Budget(max_iterations=10),
    )
    assert "user_input" in tm.allowed_controllables
    assert tm.budget.max_iterations == 10


def test_event_kind_values():
    assert EventKind.USER_INPUT == "user_input"
    assert EventKind.INJECTION == "injection"


def test_trace_event_frozen():
    e = TraceEvent(
        event_id="e1",
        parent_event_id=None,
        timestamp_ms=1000,
        actor="user",
        kind=EventKind.USER_INPUT,
        domains=frozenset({SecurityDomain.USER}),
        payload={"query": "hello"},
    )
    assert e.event_id == "e1"
    assert e.kind == EventKind.USER_INPUT


def test_action_record():
    a = ActionRecord(
        action_id="a1",
        action_type="tool_call",
        name="search",
        arguments={"q": "test"},
    )
    assert a.name == "search"


def test_turn_result():
    tr = TurnResult(action=None, observation=None, new_events=[], done=True)
    assert tr.done is True


def test_context_snapshot():
    cs = ContextSnapshot(
        user_prompt="test",
        trajectory=[],
        memory=[],
        environment_state={},
        authenticated_sources=frozenset({"user"}),
        permission_edges=frozenset(),
    )
    assert "user" in cs.authenticated_sources


def test_oracle_evidence():
    oe = OracleEvidence(name="test_oracle", value=True, confidence=0.9)
    assert oe.confidence == 0.9


def test_claim_verdict():
    cv = ClaimVerdict(
        claim_id="c1",
        property_kind=PropertyKind.TASK_ALIGNMENT,
        satisfied=True,
        score=1.0,
        evidence=[],
        explanation="Aligned",
    )
    assert cv.satisfied is True


def test_task_definition():
    td = TaskDefinition(
        task_id="t1",
        name="Test Task",
        description="A test task",
        adversarial_goal="Exfiltrate data",
    )
    assert td.adversarial_goal == "Exfiltrate data"


def test_task_feedback():
    tf = TaskFeedback(score=0.75, subscores={"utility": 0.5}, verdicts=[])
    assert tf.score == 0.75


def test_budget_usage_addition():
    a = BudgetUsage(iterations=2, cost_usd=0.5)
    b = BudgetUsage(iterations=3, cost_usd=1.0)
    c = a + b
    assert c.iterations == 5
    assert c.cost_usd == 1.5


def test_budget_estimate_unknown():
    est = BudgetEstimate.unknown()
    assert est.confidence == 0.0


def test_hierarchical_budget_exhaustion():
    hb = HierarchicalBudget(max_iterations=5)
    assert not hb.is_exhausted
    hb.record_usage(BudgetUsage(iterations=5))
    assert hb.is_exhausted


def test_hierarchical_budget_spawn_child():
    parent = HierarchicalBudget(max_iterations=10)
    child = parent.spawn_child(max_iterations=5)
    assert child.max_iterations == 5
    child.record_usage(BudgetUsage(iterations=3))
    assert parent.usage.iterations == 3
