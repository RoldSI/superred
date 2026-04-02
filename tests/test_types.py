"""Unit tests for core value types: Goal, Score, EvaluationResult, FeedbackResult,
ControllableSpec, Controllable, RequestAnswerPair, Observable, ObservableValue,
ConfigSpec, QuerySpec, QueryParam, and Event hierarchy.

Each test verifies a real behavioral contract of the type system.
"""

from __future__ import annotations

import uuid
from dataclasses import FrozenInstanceError
from datetime import datetime

import pytest

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
from superred.core.types.security_domain import SecurityDomainTag
from superred.core.types.state import ConfigSpec, QueryParam, QuerySpec
from superred.core.types.trajectory import Trajectory

# ---------------------------------------------------------------------------
# Goal
# ---------------------------------------------------------------------------


class TestGoal:
    def test_construction_requires_description(self) -> None:
        g = Goal(description="Extract secret")
        assert g.description == "Extract secret"

    def test_frozen(self) -> None:
        g = Goal(description="test")
        with pytest.raises(FrozenInstanceError):
            g.description = "other"  # type: ignore[misc]

    def test_equality(self) -> None:
        assert Goal(description="a") == Goal(description="a")
        assert Goal(description="a") != Goal(description="b")


# ---------------------------------------------------------------------------
# Score
# ---------------------------------------------------------------------------


class TestScore:
    def test_construction(self) -> None:
        tag = SecurityDomainTag("ext")
        s = Score(value=0.5, security_domain=tag)
        assert s.value == 0.5
        assert s.security_domain is tag
        assert s.name == "primary"

    def test_custom_name(self) -> None:
        tag = SecurityDomainTag("ext")
        s = Score(value=1.0, security_domain=tag, name="asr")
        assert s.name == "asr"

    def test_frozen(self) -> None:
        tag = SecurityDomainTag("ext")
        s = Score(value=0.5, security_domain=tag)
        with pytest.raises(FrozenInstanceError):
            s.value = 1.0  # type: ignore[misc]

    @pytest.mark.parametrize("value", [0.0, -1.0, 1.0, float("inf"), float("-inf")])
    def test_accepts_any_float(self, value: float) -> None:
        """Score does not constrain value range -- that's the evaluator's job."""
        tag = SecurityDomainTag("ext")
        s = Score(value=value, security_domain=tag)
        assert s.value == value

    def test_security_domain_is_required(self) -> None:
        with pytest.raises(TypeError):
            Score(value=0.5)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# EvaluationResult
# ---------------------------------------------------------------------------


class TestEvaluationResult:
    def test_required_fields(self) -> None:
        tag = SecurityDomainTag("ext")
        er = EvaluationResult(
            success=True, primary_score=Score(value=1.0, security_domain=tag),
        )
        assert er.success is True
        assert er.primary_score.value == 1.0
        assert er.sub_scores == {}
        assert er.rationale == ""

    def test_with_sub_scores_and_rationale(self) -> None:
        tag = SecurityDomainTag("ext")
        sub = {"asr": Score(value=0.9, security_domain=tag, name="asr")}
        er = EvaluationResult(
            success=False,
            primary_score=Score(value=0.5, security_domain=tag),
            sub_scores=sub,
            rationale="Partial extraction",
        )
        assert er.sub_scores["asr"].value == 0.9
        assert er.rationale == "Partial extraction"

    def test_frozen(self) -> None:
        tag = SecurityDomainTag("ext")
        er = EvaluationResult(
            success=True, primary_score=Score(value=1.0, security_domain=tag),
        )
        with pytest.raises(FrozenInstanceError):
            er.success = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# FeedbackResult
# ---------------------------------------------------------------------------


class TestFeedbackResult:
    def test_wraps_evaluation(self) -> None:
        tag = SecurityDomainTag("ext")
        ev = EvaluationResult(
            success=True, primary_score=Score(value=1.0, security_domain=tag),
        )
        fb = FeedbackResult(evaluation=ev)
        assert fb.evaluation is ev

    def test_mutable(self) -> None:
        """FeedbackResult is a mutable dataclass (not frozen)."""
        tag = SecurityDomainTag("ext")
        ev1 = EvaluationResult(
            success=True, primary_score=Score(value=1.0, security_domain=tag),
        )
        ev2 = EvaluationResult(
            success=False, primary_score=Score(value=0.0, security_domain=tag),
        )
        fb = FeedbackResult(evaluation=ev1)
        fb.evaluation = ev2
        assert fb.evaluation is ev2


# ---------------------------------------------------------------------------
# ControllableSpec
# ---------------------------------------------------------------------------


class TestControllableSpec:
    def test_construction(self) -> None:
        tag = SecurityDomainTag("ext")
        spec = ControllableSpec(name="input", security_domain=tag)
        assert spec.name == "input"
        assert spec.security_domain is tag
        assert spec.description == ""
        assert spec.value_type == "text"

    def test_frozen(self) -> None:
        tag = SecurityDomainTag("ext")
        spec = ControllableSpec(name="input", security_domain=tag)
        with pytest.raises(FrozenInstanceError):
            spec.name = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# RequestAnswerPair
# ---------------------------------------------------------------------------


class TestRequestAnswerPair:
    def test_construction(self) -> None:
        pair = RequestAnswerPair(request="hello", answer="world")
        assert pair.request == "hello"
        assert pair.answer == "world"

    def test_frozen(self) -> None:
        pair = RequestAnswerPair(request="a", answer="b")
        with pytest.raises(FrozenInstanceError):
            pair.request = "c"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Controllable
# ---------------------------------------------------------------------------


class TestControllable:
    def test_construction_with_empty_history(self) -> None:
        tag = SecurityDomainTag("ext")
        spec = ControllableSpec(name="input", security_domain=tag)
        c = Controllable(spec=spec)
        assert c.spec is spec
        assert c.history == []

    def test_history_is_mutable(self) -> None:
        tag = SecurityDomainTag("ext")
        spec = ControllableSpec(name="input", security_domain=tag)
        c = Controllable(spec=spec)
        pair = RequestAnswerPair(request="q", answer="a")
        c.history.append(pair)
        assert len(c.history) == 1
        assert c.history[0] is pair

    def test_history_default_not_shared(self) -> None:
        """Each Controllable gets its own history list."""
        tag = SecurityDomainTag("ext")
        spec = ControllableSpec(name="input", security_domain=tag)
        c1 = Controllable(spec=spec)
        c2 = Controllable(spec=spec)
        c1.history.append(RequestAnswerPair(request="q", answer="a"))
        assert len(c2.history) == 0


# ---------------------------------------------------------------------------
# Observable / ObservableValue
# ---------------------------------------------------------------------------


class TestObservable:
    def test_construction_defaults(self) -> None:
        tag = SecurityDomainTag("ext")
        obs = Observable(name="sys_desc", security_domain=tag)
        assert obs.name == "sys_desc"
        assert obs.description == ""
        assert obs.observable_type == "text"

    def test_frozen(self) -> None:
        tag = SecurityDomainTag("ext")
        obs = Observable(name="sys_desc", security_domain=tag)
        with pytest.raises(FrozenInstanceError):
            obs.name = "other"  # type: ignore[misc]


class TestObservableValue:
    def test_wraps_observable_with_content(self) -> None:
        tag = SecurityDomainTag("ext")
        obs = Observable(name="code", security_domain=tag)
        ov = ObservableValue(observable=obs, content="print('hello')")
        assert ov.observable is obs
        assert ov.content == "print('hello')"

    def test_default_content_is_none(self) -> None:
        tag = SecurityDomainTag("ext")
        obs = Observable(name="code", security_domain=tag)
        ov = ObservableValue(observable=obs)
        assert ov.content is None


# ---------------------------------------------------------------------------
# ConfigSpec / QuerySpec / QueryParam
# ---------------------------------------------------------------------------


class TestConfigSpec:
    def test_construction(self) -> None:
        tag = SecurityDomainTag("ext")
        cs = ConfigSpec(name="db_seed", security_domain=tag, description="SQL seed data")
        assert cs.name == "db_seed"
        assert cs.security_domain is tag
        assert cs.description == "SQL seed data"

    def test_frozen(self) -> None:
        tag = SecurityDomainTag("ext")
        cs = ConfigSpec(name="db_seed", security_domain=tag, description="desc")
        with pytest.raises(FrozenInstanceError):
            cs.name = "other"  # type: ignore[misc]


class TestQueryParam:
    def test_construction(self) -> None:
        qp = QueryParam(name="limit", description="Max results")
        assert qp.name == "limit"
        assert qp.description == "Max results"


class TestQuerySpec:
    def test_construction_with_defaults(self) -> None:
        qs = QuerySpec(name="get_logs", description="Retrieve audit logs")
        assert qs.name == "get_logs"
        assert qs.params == []

    def test_construction_with_params(self) -> None:
        p = QueryParam(name="limit", description="Max results")
        qs = QuerySpec(name="get_logs", description="desc", params=[p])
        assert len(qs.params) == 1
        assert qs.params[0] is p


# ---------------------------------------------------------------------------
# Event hierarchy
# ---------------------------------------------------------------------------


class TestEvent:
    def test_auto_fields(self) -> None:
        """Event auto-generates event_id (UUID) and timestamp."""
        e = Event()
        uuid.UUID(e.event_id)  # validates format, raises if invalid
        assert isinstance(e.timestamp, datetime)

    def test_unique_ids(self) -> None:
        """Each Event instance gets a unique event_id."""
        e1 = Event()
        e2 = Event()
        assert e1.event_id != e2.event_id

    def test_frozen(self) -> None:
        e = Event()
        with pytest.raises(FrozenInstanceError):
            e.event_id = "fake"  # type: ignore[misc]


class TestEventResponse:
    def test_references_event(self) -> None:
        e = Event()
        r = EventResponse(event=e)
        assert r.event is e


class TestControllableEvents:
    def test_pre_call_event_fields(self) -> None:
        tag = SecurityDomainTag("ext")
        c = Controllable(spec=ControllableSpec(name="input", security_domain=tag))
        e = ControllablePreCallEvent(controllable=c, request="hello")
        assert e.controllable is c
        assert e.request == "hello"
        assert isinstance(e, Event)

    def test_post_call_event_fields(self) -> None:
        tag = SecurityDomainTag("ext")
        c = Controllable(spec=ControllableSpec(name="input", security_domain=tag))
        e = ControllablePostCallEvent(controllable=c, request="hello", answer="world")
        assert e.answer == "world"
        assert isinstance(e, Event)

    def test_injection_response(self) -> None:
        e = Event()
        inj = ControllableInjection(event=e, value="payload")
        assert inj.value == "payload"
        assert inj.event is e
        assert isinstance(inj, EventResponse)

    def test_no_modification_response(self) -> None:
        e = Event()
        nm = NoModification(event=e)
        assert nm.event is e
        assert isinstance(nm, EventResponse)


class TestRunLifecycleEvents:
    def test_run_start_event(self) -> None:
        t = Trajectory()
        e = RunStartEvent(trajectory=t)
        assert e.trajectory is t
        assert isinstance(e, Event)

    def test_run_end_event(self) -> None:
        t = Trajectory()
        e = RunEndEvent(trajectory=t)
        assert e.trajectory is t

    def test_run_end_response_default_not_done(self) -> None:
        e = RunEndEvent(trajectory=Trajectory())
        r = RunEndResponse(event=e, done=False)
        assert r.done is False

    def test_run_end_response_done(self) -> None:
        e = RunEndEvent(trajectory=Trajectory())
        r = RunEndResponse(event=e, done=True)
        assert r.done is True
