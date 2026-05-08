"""Unit tests for ``superred.core.persistence``."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from superred.core.controller import RunResult, TaskResult, ThreatModelResult
from superred.core.persistence import (
    SCHEMA_VERSION,
    _compute_summary,
    _filename_for,
    _sanitize_segment,
    _serialize_claim_level,
    _serialize_evaluation,
    _serialize_event,
    _serialize_llm_config,
    _serialize_response,
    _serialize_score,
    _serialize_trajectory,
    _task_filename,
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
    name = _filename_for(scope, None)
    # ROOT_TAG = "root", EXTERNAL_TAG = "external" — sorted: external, root
    assert name == "external.root__no-llm.json"


def test_filename_for_with_model() -> None:
    cfg = LLMConfig(model="openai/gpt-4o-mini", api_base="x", api_key="x")
    name = _filename_for(frozenset({EXTERNAL_TAG}), cfg)
    assert name == "external__openai_gpt-4o-mini.json"


def test_filename_for_no_llm() -> None:
    name = _filename_for(frozenset({EXTERNAL_TAG}), None)
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
# _task_filename helper
# ---------------------------------------------------------------------------


def test_task_filename_pads_to_five_digits() -> None:
    assert _task_filename(1, "Goal").startswith("00001__")
    assert _task_filename(42, "Goal").startswith("00042__")
    assert _task_filename(99999, "Goal").startswith("99999__")


def test_task_filename_sanitizes_and_truncates_goal() -> None:
    long = "Inject the correct key into every controllable / regardless of trust"
    name = _task_filename(7, long)
    assert name.startswith("00007__")
    # Truncated to <=50 chars in the goal portion.
    goal_part = name.removeprefix("00007__").removesuffix(".json")
    assert len(goal_part) <= 50
    # Sanitized — no slashes or spaces.
    assert "/" not in goal_part
    assert " " not in goal_part


def test_task_filename_falls_back_to_task_when_empty() -> None:
    assert _task_filename(3, "").endswith("00003__task.json")


def test_task_filename_only_strips_underscore_not_other_chars() -> None:
    """Trailing letters must be preserved — only underscores are stripped.
    Guards against widening the rstrip charset (e.g. ``rstrip('XX_XX')``)."""
    # Goal sanitizes to "fooX_" (trailing _ from spaces); strip ONLY the _.
    assert task_filename(1, "fooX_").endswith("00001__fooX.json")
    # And X-only trailing must be left alone.
    assert task_filename(2, "barX").endswith("00002__barX.json")


# ---------------------------------------------------------------------------
# Summary aggregation
# ---------------------------------------------------------------------------


def _make_task_result(score: float, success: bool, calls: int = 0, cost: float = 0.0) -> TaskResult:
    """Helper: a minimal TaskResult with the given primary score."""
    primary = Score(value=score, security_domain=EXTERNAL_TAG)
    ev = EvaluationResult(success=success, primary_score=primary)
    return TaskResult(
        task=StubTask(),
        runs=[],
        best_score=primary,
        best_evaluation=ev,
        success=success,
        llm_usage=LLMUsage(calls=calls, cost=cost),
        stop_reason="done",
    )


def test_compute_summary_basic_aggregates() -> None:
    tmr = ThreatModelResult(
        scope=frozenset({EXTERNAL_TAG}),
        llm_config=None,
        task_results=[
            _make_task_result(0.2, success=False, calls=1, cost=0.001),
            _make_task_result(0.8, success=True, calls=4, cost=0.005),
            _make_task_result(0.5, success=False, calls=2, cost=0.002),
        ],
    )
    summary = _compute_summary(tmr)
    assert summary["n_tasks"] == 3
    assert summary["n_success"] == 1
    assert summary["n_skipped"] == 0
    assert summary["max_primary_score"] == 0.8
    assert summary["mean_primary_score"] == pytest.approx(0.5)
    assert summary["total_llm_usage"] == {"calls": 7, "cost": pytest.approx(0.008)}


def test_compute_summary_excludes_skipped_from_mean() -> None:
    """Skipped tasks aren't in task_results — they have no score and
    must not affect the mean. Only n_skipped reflects them."""
    tmr = ThreatModelResult(
        scope=frozenset({EXTERNAL_TAG}),
        llm_config=None,
        task_results=[_make_task_result(0.4, success=False)],
        skipped_tasks=[StubTask(goal_text="not applicable")],
    )
    summary = _compute_summary(tmr)
    assert summary["n_tasks"] == 1
    assert summary["n_skipped"] == 1
    assert summary["mean_primary_score"] == 0.4


def test_compute_summary_no_tasks_yields_null_score() -> None:
    """When the claim has no tasks (or all skipped), score aggregates
    are None rather than crashing on division by zero."""
    tmr = ThreatModelResult(
        scope=frozenset({EXTERNAL_TAG}),
        llm_config=None,
        task_results=[],
        skipped_tasks=[StubTask(goal_text="x"), StubTask(goal_text="y")],
    )
    summary = _compute_summary(tmr)
    assert summary["n_tasks"] == 0
    assert summary["n_skipped"] == 2
    assert summary["max_primary_score"] is None
    assert summary["mean_primary_score"] is None
    assert summary["total_llm_usage"] == {"calls": 0, "cost": 0.0}


# ---------------------------------------------------------------------------
# End-to-end: write_threat_model_result + _serialize_claim_level
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
        task_results=[task_result],
        skipped_tasks=[],
    )


def test_serialize_claim_level_shape() -> None:
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    summaries = [{"task": {"goal": "Test goal"}, "file": "external__m/00001__Test_goal.json"}]
    payload = _serialize_claim_level(tmr, summaries)
    assert payload["version"] == SCHEMA_VERSION
    datetime.fromisoformat(payload["completed_at"].replace("Z", "+00:00"))
    assert payload["scope"] == ["external"]
    assert payload["llm_config"] == {"model": "m", "max_cost": None}
    assert payload["summary"]["n_tasks"] == 1
    assert payload["summary"]["n_success"] == 1
    assert payload["summary"]["mean_primary_score"] == 0.7
    assert payload["summary"]["max_primary_score"] == 0.7
    assert payload["task_results"] == summaries
    assert payload["skipped_tasks"] == []


def test_write_threat_model_result_creates_layout(tmp_path: Path) -> None:
    """One claim file in main folder, one detail file per task in subfolder."""
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    written = write_threat_model_result(tmr, tmp_path)
    assert written == tmp_path / "external__m.json"
    subfolder = tmp_path / "external__m"
    assert subfolder.is_dir()
    detail_files = sorted(subfolder.glob("*.json"))
    assert len(detail_files) == 1
    assert detail_files[0].name.startswith("00001__")
    # No leftover .tmp files anywhere.
    assert not list(tmp_path.rglob("*.tmp"))


def test_claim_file_links_to_detail_with_relative_path(tmp_path: Path) -> None:
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    claim = write_threat_model_result(tmr, tmp_path)
    parsed = json.loads(claim.read_text())
    entry = parsed["task_results"][0]
    rel = entry["file"]
    # Path is relative to results_dir and points at an actual file.
    assert (tmp_path / rel).exists()
    assert rel.startswith("external__m/")
    assert rel.endswith(".json")
    # Claim entry has the summary fields, NOT the trajectory.
    assert "trajectory" not in entry
    assert entry["n_runs"] == 1
    assert entry["stop_reason"] == "done"
    assert entry["best_score"]["value"] == 0.7


def test_detail_file_is_self_contained(tmp_path: Path) -> None:
    """A detail file carries its own scope/llm_config so it is meaningful
    in isolation."""
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    write_threat_model_result(tmr, tmp_path)
    detail_files = list((tmp_path / "external__m").glob("*.json"))
    assert len(detail_files) == 1
    detail = json.loads(detail_files[0].read_text())
    assert detail["version"] == SCHEMA_VERSION
    assert detail["scope"] == ["external"]
    assert detail["llm_config"] == {"model": "m", "max_cost": None}
    assert detail["task"]["goal"] == "Test goal"
    assert detail["stop_reason"] == "done"
    assert len(detail["runs"]) == 1
    assert detail["runs"][0]["run_number"] == 1
    assert "trajectory" in detail["runs"][0]


def test_no_secret_in_any_written_file(tmp_path: Path) -> None:
    """``api_key`` and ``api_base`` are excluded from BOTH the claim
    file and every detail file."""
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    write_threat_model_result(tmr, tmp_path)
    for path in tmp_path.rglob("*.json"):
        text = path.read_text()
        assert "SECRET" not in text
        assert "api_key" not in text
        assert "api_base" not in text


def test_write_threat_model_result_creates_directory(tmp_path: Path) -> None:
    target_dir = tmp_path / "nested" / "results"
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    write_threat_model_result(tmr, target_dir)
    assert (target_dir / "external__m.json").exists()
    assert (target_dir / "external__m" / "00001__Test_goal.json").exists()


def test_write_threat_model_result_refuses_overwrite_claim(tmp_path: Path) -> None:
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    write_threat_model_result(tmr, tmp_path)
    with pytest.raises(FileExistsError):
        write_threat_model_result(tmr, tmp_path)


def test_write_threat_model_result_refuses_existing_subfolder(tmp_path: Path) -> None:
    """Pre-existing subfolder (without claim file) also blocks writes."""
    (tmp_path / "external__m").mkdir()
    tmr = _build_minimal_tmr(frozenset({EXTERNAL_TAG}))
    with pytest.raises(FileExistsError):
        write_threat_model_result(tmr, tmp_path)


def test_json_fallback_repr_for_arbitrary_object(tmp_path: Path) -> None:
    """Non-datetime, non-JSON-native objects in trajectory content fall
    back to ``repr`` rather than crashing the write. Trajectory lives
    in the per-task detail file under the new layout."""

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
        task_results=[tr],
    )
    write_threat_model_result(tmr, tmp_path)
    detail = json.loads(next((tmp_path / "external__no-llm").glob("*.json")).read_text())
    content = detail["runs"][0]["trajectory"][0]["content"]
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
        task_results=[tr],
    )
    write_threat_model_result(tmr, tmp_path)
    detail = json.loads(next((tmp_path / "external__no-llm").glob("*.json")).read_text())
    content = detail["runs"][0]["trajectory"][0]["content"]
    assert "2026-01-01T12:00:00" in content
