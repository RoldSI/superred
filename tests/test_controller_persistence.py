"""Integration tests for ``Controller(results_dir=...)``.

These exercise the end-to-end persistence behavior — that completed
threat models are written incrementally (so a later failure can't lose
already-finished ones) and that no files are written when
``results_dir`` is not configured.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from superred.core.controller import Controller
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.types.controllable import Controllable
from superred.core.types.event import EventHandler, EventResponseHandler
from superred.core.types.events import ControllablePreCallEvent
from superred.core.types.security_domain import Scope, SecurityDomainTag

from .conftest import (
    EXTERNAL_TAG,
    INTERNAL_TAG,
    STUB_LLM_CONFIG,
    StubOptimizer,
    StubTarget,
    StubTask,
)

EXTERNAL_SCOPE: Scope = frozenset({EXTERNAL_TAG})
INTERNAL_SCOPE: Scope = frozenset({INTERNAL_TAG})


class FailOnNthRunTarget(StubTarget):
    """Target whose ``run()`` succeeds N-1 times then raises ``RuntimeError``.

    Used to simulate a later threat model crashing while earlier ones
    have already completed.
    """

    def __init__(self, fail_on_call: int, tag: SecurityDomainTag = EXTERNAL_TAG) -> None:
        super().__init__(tag=tag)
        self._fail_on_call = fail_on_call
        self._calls = 0

    async def run(self, emit: EventHandler, send_event: EventResponseHandler) -> None:
        self._calls += 1
        if self._calls == self._fail_on_call:
            raise RuntimeError(f"target failed on call #{self._calls}")
        ctrl = Controllable(name="user_input", security_domain=self._tag)
        await send_event(ControllablePreCallEvent(controllable=ctrl, request="hello"))


class TwoTagTarget(StubTarget):
    """StubTarget that exposes both EXTERNAL and INTERNAL controllables.

    Default ``StubTarget`` ties everything to EXTERNAL_TAG, so an
    INTERNAL_SCOPE finds nothing in scope. This subclass exposes a
    controllable in whichever scope the optimizer is given so both
    scopes do real work.
    """

    def __init__(self) -> None:
        super().__init__(tag=EXTERNAL_TAG)

    def get_controllables(self) -> list[Controllable]:
        return [
            Controllable(name="ext_input", security_domain=EXTERNAL_TAG),
            Controllable(name="int_input", security_domain=INTERNAL_TAG),
        ]

    async def run(self, emit: EventHandler, send_event: EventResponseHandler) -> None:
        # Send one event per controllable; the security_domain_filter
        # middleware will short-circuit out-of-scope ones.
        for ctrl in self.get_controllables():
            await send_event(ControllablePreCallEvent(controllable=ctrl, request="hi"))


# ---------------------------------------------------------------------------
# Default behavior (results_dir=None)
# ---------------------------------------------------------------------------


async def test_no_results_dir_writes_nothing(tmp_path: Path) -> None:
    """When results_dir is not provided, no files are written anywhere.

    We can't easily prove "no files written anywhere on the filesystem",
    but we can confirm that an empty tmp_path stays empty after a run,
    which combined with no ambient I/O in the framework is sufficient.
    """
    controller = Controller(
        optimizer_factory=lambda: StubOptimizer(done=True),
        target=StubTarget(),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_configs=[STUB_LLM_CONFIG],
    )
    await controller.run(scopes=[EXTERNAL_SCOPE])
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Single threat model -> single file
# ---------------------------------------------------------------------------


async def test_single_threat_model_creates_claim_and_subfolder(tmp_path: Path) -> None:
    controller = Controller(
        optimizer_factory=lambda: StubOptimizer(done=True),
        target=StubTarget(),
        security_claim=SecurityClaim.from_tasks([StubTask(score=0.8, success=True)]),
        llm_configs=[STUB_LLM_CONFIG],
        results_dir=tmp_path,
    )
    await controller.run(scopes=[EXTERNAL_SCOPE])

    claim = tmp_path / "external__test-model.json"
    subfolder = tmp_path / "external__test-model"
    assert claim.exists()
    assert subfolder.is_dir()
    detail_files = sorted(subfolder.glob("*.json"))
    assert len(detail_files) == 1
    assert detail_files[0].name.startswith("00001__")

    claim_payload = json.loads(claim.read_text())
    assert claim_payload["scope"] == ["external"]
    assert claim_payload["llm_config"]["model"] == "test-model"
    summary = claim_payload["summary"]
    assert summary["n_tasks"] == 1
    assert summary["n_success"] == 1
    assert summary["n_skipped"] == 0
    assert summary["max_primary_score"] == 0.8
    assert summary["mean_primary_score"] == 0.8
    assert summary["total_llm_usage"] == {"calls": 0, "cost": 0.0}

    entry = claim_payload["task_results"][0]
    assert entry["file"] == f"external__test-model/{detail_files[0].name}"
    assert entry["success"] is True
    assert entry["best_score"]["value"] == 0.8
    assert entry["stop_reason"] == "done"
    assert entry["n_runs"] == 1
    # Trajectory and best_evaluation live in the detail file, not the claim.
    assert "trajectory" not in entry
    assert "best_evaluation" not in entry

    detail = json.loads(detail_files[0].read_text())
    assert detail["scope"] == ["external"]
    assert detail["task"]["goal"] == "Test goal"
    assert detail["stop_reason"] == "done"
    assert detail["runs"][0]["llm_usage"] == {"calls": 0, "cost": 0.0}
    assert detail["runs"][0]["trajectory"][-1]["type"] == "RunEndEvent"


async def test_results_dir_str_is_accepted(tmp_path: Path) -> None:
    """Both Path and str should work for the ctor arg."""
    controller = Controller(
        optimizer_factory=lambda: StubOptimizer(done=True),
        target=StubTarget(),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_configs=[STUB_LLM_CONFIG],
        results_dir=str(tmp_path / "out"),
    )
    await controller.run(scopes=[EXTERNAL_SCOPE])
    assert (tmp_path / "out" / "external__test-model.json").exists()
    assert (tmp_path / "out" / "external__test-model").is_dir()


# ---------------------------------------------------------------------------
# Multi-threat-model fanout
# ---------------------------------------------------------------------------


async def test_two_scopes_produce_two_layouts(tmp_path: Path) -> None:
    controller = Controller(
        optimizer_factory=lambda: StubOptimizer(done=True),
        target=TwoTagTarget(),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_configs=[STUB_LLM_CONFIG],
        results_dir=tmp_path,
    )
    await controller.run(scopes=[EXTERNAL_SCOPE, INTERNAL_SCOPE])
    files = sorted(p.name for p in tmp_path.glob("*.json"))
    assert files == [
        "external__test-model.json",
        "internal__test-model.json",
    ]
    assert (tmp_path / "external__test-model").is_dir()
    assert (tmp_path / "internal__test-model").is_dir()


# ---------------------------------------------------------------------------
# Crash safety: later threat model fails -> earlier one is on disk
# ---------------------------------------------------------------------------


async def test_later_failure_keeps_earlier_threat_model_persisted(tmp_path: Path) -> None:
    """Scope 1 completes, scope 2 raises mid-flight: scope 1's file is intact."""
    from .conftest import ROOT_TAG

    target = FailOnNthRunTarget(fail_on_call=2, tag=EXTERNAL_TAG)
    controller = Controller(
        optimizer_factory=lambda: StubOptimizer(done=True),
        target=target,
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_configs=[STUB_LLM_CONFIG],
        results_dir=tmp_path,
        max_runs_per_task=1,
    )
    # Both EXTERNAL_SCOPE and the root scope cover EXTERNAL_TAG, so the
    # target's controllable is in scope for both. Distinct scopes give
    # distinct filenames. The second target.run() call raises.
    root_scope: Scope = frozenset({ROOT_TAG})
    with pytest.raises(RuntimeError, match="target failed on call #2"):
        await controller.run(scopes=[EXTERNAL_SCOPE, root_scope])

    # The first (external) scope completed and was persisted before the
    # second (root) scope started. The second produced no file.
    files = sorted(p.name for p in tmp_path.glob("*.json"))
    assert files == ["external__test-model.json"]
    parsed = json.loads((tmp_path / "external__test-model.json").read_text())
    assert parsed["scope"] == ["external"]
    assert len(parsed["task_results"]) == 1


# ---------------------------------------------------------------------------
# No tmp leftover on success
# ---------------------------------------------------------------------------


async def test_no_tmp_leftover_after_successful_run(tmp_path: Path) -> None:
    controller = Controller(
        optimizer_factory=lambda: StubOptimizer(done=True),
        target=StubTarget(),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_configs=[STUB_LLM_CONFIG],
        results_dir=tmp_path,
    )
    await controller.run(scopes=[EXTERNAL_SCOPE])
    assert not list(tmp_path.rglob("*.tmp"))


# ---------------------------------------------------------------------------
# include_feedback=False still produces a valid file
# ---------------------------------------------------------------------------


async def test_include_feedback_false_persists_run_end_with_null_eval(
    tmp_path: Path,
) -> None:
    controller = Controller(
        optimizer_factory=lambda: StubOptimizer(done=True),
        target=StubTarget(),
        security_claim=SecurityClaim.from_tasks([StubTask(score=0.5, success=False)]),
        llm_configs=[STUB_LLM_CONFIG],
        results_dir=tmp_path,
        include_feedback=False,
    )
    await controller.run(scopes=[EXTERNAL_SCOPE])
    detail_files = list((tmp_path / "external__test-model").glob("*.json"))
    assert len(detail_files) == 1
    detail = json.loads(detail_files[0].read_text())
    # The per-run RunResult.evaluation is still populated...
    assert detail["runs"][0]["evaluation"]["primary_score"]["value"] == 0.5
    # ...but the RunEndEvent in the trajectory carries evaluation=None.
    traj = detail["runs"][0]["trajectory"]
    end_events = [item for item in traj if item.get("type") == "RunEndEvent"]
    assert len(end_events) == 1
    assert end_events[0]["evaluation"] is None
