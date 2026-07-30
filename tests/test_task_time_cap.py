"""Per-task wall-clock bound: ``Controller(task_time_cap_s=...)``.

The existing per-task bounds (``task_cost_cap_usd``, ``max_runs_per_task``)
bound the WORK a task may do. Neither can stop a task whose provider call
blocks forever: no spend accrues and no run completes, so the task hangs until
something outside the framework kills the whole process. These tests pin the
wall-clock bound that does stop it, and pin that a timed-out task is never
mistaken for a measurement.
"""

from __future__ import annotations

import asyncio

import pytest

from superred.core.controller import Controller, TargetFactory
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.persistence import _KEPT_STATUSES, _compute_summary, _status_of
from superred.core.types.event import EventHandler, EventResponseHandler
from superred.core.types.security_domain import Scope

from .conftest import EXTERNAL_TAG, STUB_LLM_CONFIG, StubOptimizer, StubTarget, StubTask

EXTERNAL_SCOPE: Scope = frozenset({EXTERNAL_TAG})


class HangingTarget(StubTarget):
    """Blocks forever without spending anything.

    This is precisely the shape the work bounds cannot catch: no LLM cost
    accrues, so ``task_cost_cap_usd`` never trips, and no run ever completes,
    so ``max_runs_per_task`` never trips either.
    """

    async def run(self, emit: EventHandler, send_event: EventResponseHandler) -> None:
        await asyncio.Event().wait()


def test_rejects_a_non_positive_cap() -> None:
    for bad in (0, -1.5):
        with pytest.raises(ValueError, match="task_time_cap_s must be positive"):
            Controller(
                scope=EXTERNAL_SCOPE,
                optimizer_factory=lambda: StubOptimizer(),
                target_factory=TargetFactory.singleton(StubTarget()),
                security_claim=SecurityClaim.from_tasks([StubTask()]),
                llm_config=STUB_LLM_CONFIG,
                task_time_cap_s=bad,
            )


def test_timeout_is_not_a_resumable_kept_status() -> None:
    """A resume must recompute a timed-out task, never carry it forward."""
    assert _status_of(False, "timeout") == "timeout"
    assert "timeout" not in _KEPT_STATUSES


def test_timeout_is_excluded_from_the_asr_denominator() -> None:
    """A task that never finished is not evidence that the attack failed."""

    class View:
        def __init__(self, stop_reason: str, success: bool) -> None:
            self.stop_reason = stop_reason
            self.success = success
            self.best_score = 0.0
            self.calls = 0
            self.cost = 0.0

    summary = _compute_summary(
        [View("done", True), View("done", False), View("timeout", False)],  # type: ignore[list-item]
        n_skipped=0,
    )
    assert summary["n_timeout"] == 1
    assert summary["n_completed"] == 2
    assert summary["asr"] == pytest.approx(0.5)


@pytest.mark.asyncio
async def test_a_hanging_task_is_cancelled_and_recorded_as_timeout() -> None:
    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(),
        target_factory=TargetFactory(create=HangingTarget),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_config=STUB_LLM_CONFIG,
        task_time_cap_s=0.25,
        report=False,
    )
    result = await asyncio.wait_for(controller.run(), timeout=20)

    assert len(result.task_results) == 1
    tr = result.task_results[0]
    assert tr.stop_reason == "timeout"
    assert tr.success is False
    assert "task_time_cap_s" in (tr.best_evaluation.rationale or "")


@pytest.mark.asyncio
async def test_the_cap_bounds_each_task_independently() -> None:
    """Three hanging tasks each time out; one slow task cannot consume another's budget."""
    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(),
        target_factory=TargetFactory(create=HangingTarget, concurrency=3),
        security_claim=SecurityClaim.from_tasks(
            [StubTask(goal_text="a"), StubTask(goal_text="b"), StubTask(goal_text="c")]
        ),
        llm_config=STUB_LLM_CONFIG,
        task_time_cap_s=0.25,
        report=False,
    )
    result = await asyncio.wait_for(controller.run(), timeout=20)
    assert [tr.stop_reason for tr in result.task_results] == ["timeout"] * 3


@pytest.mark.asyncio
async def test_default_is_unbounded_and_changes_nothing() -> None:
    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory.singleton(StubTarget()),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_config=STUB_LLM_CONFIG,
        report=False,
    )
    result = await controller.run()
    assert result.task_results[0].stop_reason != "timeout"


@pytest.mark.asyncio
async def test_a_task_that_finishes_inside_the_cap_is_untouched() -> None:
    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory.singleton(StubTarget()),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_config=STUB_LLM_CONFIG,
        task_time_cap_s=30,
        report=False,
    )
    result = await controller.run()
    tr = result.task_results[0]
    assert tr.stop_reason == "done"
