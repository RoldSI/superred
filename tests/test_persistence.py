"""Unit tests for ``superred.core.persistence``."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from superred.core.controller import (
    ControllerConfig,
    RunResult,
    TaskResult,
    ThreatModelResult,
)
from superred.core.persistence import (
    SCHEMA_VERSION,
    _sanitize_segment,
    _serialize_evaluation,
    _serialize_event,
    _serialize_llm_config,
    _serialize_response,
    _serialize_score,
    _serialize_trajectory,
    filename_for,
    serialize_threat_model_result,
    write_threat_model_result,
)
from superred.core.types.controllable import Controllable
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.events import (
    ControllableInjection,
    ControllableNoInjection,
    ControllablePostCallEvent,
    ControllablePreCallEvent,
    ObservableEvent,
    RunEndEvent,
    RunEndResponse,
)
from superred.core.types.llm import LLMConfig, LLMUsage
from superred.core.types.observable import Observable
from superred.core.types.security_domain import SecurityDomainTag
from superred.core.types.trajectory import Trajectory

from .conftest import EXTERNAL_TAG, ROOT_TAG, StubTask

# ---------------------------------------------------------------------------
# Sanitization & filenames
# ---------------------------------------------------------------------------


def test_sanitize_segment_keeps_safe_chars() -> None:
    assert _sanitize_segment("abcXYZ_-09") == "abcXYZ_-09"


def test_sanitize_segment_replaces_unsafe() -> None:
    assert _sanitize_segment("openai/gpt-4o-mini") == "openai_gpt-4o-mini"
    assert _sanitize_segment("a b.c:d") == "a_b_c_d"


def test_filename_for_sorts_scope() -> None:
    scope = frozenset({EXTERNAL_TAG, ROOT_TAG})
    name = filename_for(scope, None)
    # ROOT_TAG = "root", EXTERNAL_TAG = "external" — sorted: external, root
    assert name == "external.root__no-llm.json"


def test_filename_for_with_model() -> None:
    cfg = LLMConfig(model="openai/gpt-4o-mini", api_base="x", api_key="x")
    name = filename_for(frozenset({EXTERNAL_TAG}), cfg)
    assert name == "external__openai_gpt-4o-mini.json"


def test_filename_for_no_llm() -> None:
    name = filename_for(frozenset({EXTERNAL_TAG}), None)
    assert name == "external__no-llm.json"


# ---------------------------------------------------------------------------
# LLMConfig allowlist (secret-leak guard)
# ---------------------------------------------------------------------------


def test_llm_config_excludes_api_key_and_base() -> None:
    cfg = LLMConfig(
        model="gpt-4o-mini",
        api_base="https://internal.example.com/secret-path",
        api_key="sk-LIVE-DO-NOT-LEAK",
        max_cost=1.5,
    )
    payload = _serialize_llm_config(cfg)
    assert payload == {"model": "gpt-4o-mini", "max_cost": 1.5}
    blob = json.dumps(payload)
    assert "sk-LIVE-DO-NOT-LEAK" not in blob
    assert "internal.example.com" not in blob
    assert "api_key" not in blob
    assert "api_base" not in blob


def test_llm_config_none() -> None:
    assert _serialize_llm_config(None) is None


# ---------------------------------------------------------------------------
# Score / EvaluationResult
# ---------------------------------------------------------------------------


def test_serialize_score_with_domain() -> None:
    s = Score(value=0.5, security_domain=EXTERNAL_TAG, name="asr")
    assert _serialize_score(s) == {
        "name": "asr",
        "value": 0.5,
        "security_domain": "external",
    }


def test_serialize_score_no_domain_is_null() -> None:
    s = Score(value=1.0)
    assert _serialize_score(s)["security_domain"] is None


def test_serialize_evaluation_round_trips_fields() -> None:
    primary = Score(value=0.9, security_domain=EXTERNAL_TAG)
    sub = {"asr": Score(value=0.3, security_domain=EXTERNAL_TAG)}
    ev = EvaluationResult(success=True, primary_score=primary, sub_scores=sub, rationale="because")
    out = _serialize_evaluation(ev)
    assert out["success"] is True
    assert out["primary_score"]["value"] == 0.9
    assert out["sub_scores"]["asr"]["value"] == 0.3
    assert out["rationale"] == "because"


# ---------------------------------------------------------------------------
# Events & responses
# ---------------------------------------------------------------------------


def test_serialize_pre_call_event() -> None:
    ctrl = Controllable(name="user_msg", security_domain=EXTERNAL_TAG, description="desc")
    ev = ControllablePreCallEvent(controllable=ctrl, request="hello")
    out = _serialize_event(ev)
    assert out["kind"] == "event"
    assert out["type"] == "ControllablePreCallEvent"
    assert out["security_domain"] == "external"
    assert out["controllable"]["name"] == "user_msg"
    assert out["controllable"]["security_domain"] == "external"
    assert out["request"] == "hello"
    # base fields present
    assert "event_id" in out
    datetime.fromisoformat(out["timestamp"])


def test_serialize_post_call_event() -> None:
    ctrl = Controllable(name="resp", security_domain=EXTERNAL_TAG)
    ev = ControllablePostCallEvent(controllable=ctrl, request="q", answer="a")
    out = _serialize_event(ev)
    assert out["request"] == "q"
    assert out["answer"] == "a"


def test_serialize_observable_event() -> None:
    obs = Observable(name="log", security_domain=EXTERNAL_TAG, description="d")
    ev = ObservableEvent(observable=obs, content={"k": "v"})
    out = _serialize_event(ev)
    assert out["type"] == "ObservableEvent"
    assert out["observable"]["name"] == "log"
    assert out["content"] == {"k": "v"}


def test_serialize_run_end_event_with_eval() -> None:
    ev = RunEndEvent(
        evaluation=EvaluationResult(
            success=False,
            primary_score=Score(value=0.0, security_domain=EXTERNAL_TAG),
        ),
        security_domain=EXTERNAL_TAG,
    )
    out = _serialize_event(ev)
    assert out["type"] == "RunEndEvent"
    assert out["evaluation"]["success"] is False


def test_serialize_run_end_event_without_eval() -> None:
    ev = RunEndEvent(security_domain=EXTERNAL_TAG)
    out = _serialize_event(ev)
    assert out["evaluation"] is None


def test_serialize_response_injection() -> None:
    ctrl = Controllable(name="c", security_domain=EXTERNAL_TAG)
    base = ControllablePreCallEvent(controllable=ctrl, request="r")
    inj = ControllableInjection(event=base, controllable=ctrl, value="payload")
    out = _serialize_response(inj)
    assert out == {
        "kind": "response",
        "type": "ControllableInjection",
        "controllable": "c",
        "value": "payload",
    }


def test_serialize_response_no_injection() -> None:
    ctrl = Controllable(name="c", security_domain=EXTERNAL_TAG)
    base = ControllablePreCallEvent(controllable=ctrl, request="r")
    no_inj = ControllableNoInjection(event=base, controllable=ctrl)
    out = _serialize_response(no_inj)
    assert out["type"] == "ControllableNoInjection"
    assert out["controllable"] == "c"


def test_serialize_run_end_response() -> None:
    ev = RunEndEvent(security_domain=EXTERNAL_TAG)
    resp = RunEndResponse(event=ev, done=True)
    out = _serialize_response(resp)
    assert out == {"kind": "response", "type": "RunEndResponse", "done": True}


def test_serialize_trajectory_preserves_order() -> None:
    traj = Trajectory()
    ctrl = Controllable(name="c", security_domain=EXTERNAL_TAG)
    e1 = ControllablePreCallEvent(controllable=ctrl, request="q")
    inj = ControllableInjection(event=e1, controllable=ctrl, value="v")
    e2 = RunEndEvent(security_domain=EXTERNAL_TAG)
    traj.emit(e1)
    traj.emit(inj)
    traj.emit(e2)
    items = _serialize_trajectory(traj)
    assert [i["type"] for i in items] == [
        "ControllablePreCallEvent",
        "ControllableInjection",
        "RunEndEvent",
    ]
    assert items[0]["kind"] == "event"
    assert items[1]["kind"] == "response"


# ---------------------------------------------------------------------------
# End-to-end: serialize_threat_model_result + write_threat_model_result
# ---------------------------------------------------------------------------


def _build_minimal_tmr(scope: frozenset[SecurityDomainTag]) -> ThreatModelResult:
    """Build a small ThreatModelResult for round-trip tests."""
    traj = Trajectory()
    end = RunEndEvent(security_domain=EXTERNAL_TAG)
    traj.emit(end)
    primary = Score(value=0.7, security_domain=EXTERNAL_TAG)
    eval_result = EvaluationResult(success=True, primary_score=primary)
    run = RunResult(trajectory=traj, evaluation=eval_result, llm_usage=LLMUsage(calls=2, cost=0.01))
    task = StubTask()
    task_result = TaskResult(
        task=task,
        runs=[run],
        best_score=primary,
        best_evaluation=eval_result,
        success=True,
        llm_usage=LLMUsage(calls=2, cost=0.01),
        stop_reason="done",
    )
    return ThreatModelResult(
        scope=scope,
        llm_config=LLMConfig(model="m", api_base="x", api_key="SECRET"),
        controller_config=ControllerConfig(max_runs_per_task=100, include_feedback=True),
        task_results=[task_result],
        skipped_tasks=[],
    )


def test_serialize_threat_model_result_shape() -> None:
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    payload = serialize_threat_model_result(tmr)
    assert payload["version"] == SCHEMA_VERSION
    datetime.fromisoformat(payload["completed_at"].replace("Z", "+00:00"))
    assert payload["scope"] == ["external"]
    assert payload["llm_config"] == {"model": "m", "max_cost": None}
    assert payload["controller_config"] == {"max_runs_per_task": 100, "include_feedback": True}
    assert len(payload["task_results"]) == 1
    tr = payload["task_results"][0]
    assert tr["task"]["goal"] == "Test goal"
    assert tr["success"] is True
    assert tr["stop_reason"] == "done"
    assert tr["runs"][0]["run_number"] == 1
    assert tr["runs"][0]["llm_usage"] == {"calls": 2, "cost": 0.01}
    assert payload["skipped_tasks"] == []


def test_write_threat_model_result_atomic_and_named(tmp_path: Path) -> None:
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    written = write_threat_model_result(tmr, tmp_path)
    assert written == tmp_path / "external__m.json"
    assert written.exists()
    # No leftover .tmp file after a clean write.
    assert not list(tmp_path.glob("*.tmp"))
    parsed = json.loads(written.read_text())
    assert parsed["scope"] == ["external"]
    # Secret never makes it to disk.
    assert "SECRET" not in written.read_text()


def test_write_threat_model_result_creates_directory(tmp_path: Path) -> None:
    target_dir = tmp_path / "nested" / "results"
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    write_threat_model_result(tmr, target_dir)
    assert target_dir.exists()
    assert (target_dir / "external__m.json").exists()


def test_write_threat_model_result_refuses_overwrite(tmp_path: Path) -> None:
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    write_threat_model_result(tmr, tmp_path)
    with pytest.raises(FileExistsError):
        write_threat_model_result(tmr, tmp_path)


def test_json_fallback_repr_for_arbitrary_object(tmp_path: Path) -> None:
    """Non-datetime, non-JSON-native objects in trajectory content fall
    back to ``repr`` rather than crashing the write."""

    class Opaque:
        def __repr__(self) -> str:
            return "<Opaque sentinel>"

    traj = Trajectory()
    obs = Observable(name="o", security_domain=EXTERNAL_TAG)
    traj.emit(ObservableEvent(observable=obs, content=Opaque()))
    traj.emit(RunEndEvent(security_domain=EXTERNAL_TAG))
    primary = Score(value=0.0, security_domain=EXTERNAL_TAG)
    ev = EvaluationResult(success=False, primary_score=primary)
    run = RunResult(trajectory=traj, evaluation=ev, llm_usage=LLMUsage())
    task = StubTask()
    tr = TaskResult(
        task=task,
        runs=[run],
        best_score=primary,
        best_evaluation=ev,
        success=False,
        llm_usage=LLMUsage(),
        stop_reason="max_runs",
    )
    tmr = ThreatModelResult(
        scope=frozenset({EXTERNAL_TAG}),
        llm_config=None,
        controller_config=ControllerConfig(max_runs_per_task=100, include_feedback=True),
        task_results=[tr],
    )
    written = write_threat_model_result(tmr, tmp_path)
    parsed = json.loads(written.read_text())
    content = parsed["task_results"][0]["runs"][0]["trajectory"][0]["content"]
    assert content == "<Opaque sentinel>"


def test_write_handles_non_json_native_content(tmp_path: Path) -> None:
    """Trajectory content typed as Any may include datetime/objects."""
    traj = Trajectory()
    obs = Observable(name="o", security_domain=EXTERNAL_TAG)
    ts = datetime(2026, 1, 1, 12, 0, 0)
    traj.emit(ObservableEvent(observable=obs, content=ts))
    traj.emit(RunEndEvent(security_domain=EXTERNAL_TAG))
    primary = Score(value=0.0, security_domain=EXTERNAL_TAG)
    ev = EvaluationResult(success=False, primary_score=primary)
    run = RunResult(trajectory=traj, evaluation=ev, llm_usage=LLMUsage())
    task = StubTask()
    tr = TaskResult(
        task=task,
        runs=[run],
        best_score=primary,
        best_evaluation=ev,
        success=False,
        llm_usage=LLMUsage(),
        stop_reason="max_runs",
    )
    tmr = ThreatModelResult(
        scope=frozenset({EXTERNAL_TAG}),
        llm_config=None,
        controller_config=ControllerConfig(max_runs_per_task=100, include_feedback=True),
        task_results=[tr],
    )
    written = write_threat_model_result(tmr, tmp_path)
    parsed = json.loads(written.read_text())
    content = parsed["task_results"][0]["runs"][0]["trajectory"][0]["content"]
    assert "2026-01-01T12:00:00" in content
