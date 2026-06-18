"""Tests for per-task dynamic scoping.

The Controller ``scope`` parameter accepts either a fixed ``Scope`` (the
classic behavior) or a ``ScopeResolver`` (``Callable[[Task], Scope]``) resolved
once per task.  These tests cover the resolver contract (called once per task,
receives the task, result is used), per-task gating of every optimizer-facing
surface, construction validation, the skip/error containment paths, and the new
``TaskResult.scope`` / ``TaskResult.read_only`` and
``ThreatModelResult.scope_label`` fields.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from superred.core.controller import Controller, TargetFactory, ThreatModelResult
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.interfaces.target import Target
from superred.core.interfaces.task import NotApplicable, Task
from superred.core.types.events import (
    ControllableInjection,
    ControllableNoInjection,
    ControllablePreCallEvent,
    RunEndEvent,
)
from superred.core.types.security_domain import Scope

from .conftest import (
    EXTERNAL_TAG,
    INTERNAL_TAG,
    ROOT_TAG,
    STUB_LLM_CONFIG,
    StubOptimizer,
    StubTarget,
    StubTask,
)
from .test_controller import (
    _CapturingOptimizer,
    _MultiControllableTarget,
    _ScopedScoresTask,
    _TwoChannelTarget,
)

EXTERNAL_SCOPE: Scope = frozenset({EXTERNAL_TAG})
INTERNAL_SCOPE: Scope = frozenset({INTERNAL_TAG})
ROOT_SCOPE: Scope = frozenset({ROOT_TAG})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _TaggedTask(StubTask):
    """A StubTask carrying a tag a resolver can dispatch on."""

    def __init__(self, goal_text: str, want: Scope) -> None:
        super().__init__(goal_text=goal_text)
        self.want = want


# ---------------------------------------------------------------------------
# Resolver contract: called once per task, receives the task, result is used
# ---------------------------------------------------------------------------


class TestResolverContract:
    async def test_resolver_called_once_per_task(self) -> None:
        """The resolver runs exactly once per task — not per run, not at init."""
        calls: list[Task[Target]] = []

        def resolver(task: Task[Target]) -> Scope:
            calls.append(task)
            return EXTERNAL_SCOPE

        a, b = StubTask(goal_text="a"), StubTask(goal_text="b")
        controller = Controller(
            scope=resolver,
            scope_label="dyn",
            # Many runs per task: the resolver must NOT be re-invoked per run.
            optimizer_factory=lambda: StubOptimizer(done=False),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([a, b]),
            llm_config=STUB_LLM_CONFIG,
            max_runs_per_task=4,
        )
        await controller.run()
        # Two tasks -> exactly two resolver calls (despite 4 runs each).
        assert len(calls) == 2

    async def test_resolver_receives_the_task(self) -> None:
        """The resolver is handed the very Task object it must scope."""
        seen: list[Task[Target]] = []

        def resolver(task: Task[Target]) -> Scope:
            seen.append(task)
            return EXTERNAL_SCOPE

        a, b = StubTask(goal_text="a"), StubTask(goal_text="b")
        controller = Controller(
            scope=resolver,
            scope_label="dyn",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([a, b]),
            llm_config=STUB_LLM_CONFIG,
        )
        await controller.run()
        # Same identities, in input order (results land in input order).
        assert seen == [a, b]

    async def test_resolver_result_is_used_not_a_default(self) -> None:
        """The resolved scope actually gates: a resolver returning INTERNAL
        lets an INTERNAL controllable through where a default/empty/EXTERNAL
        scope would have declined it."""
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            scope=lambda _t: INTERNAL_SCOPE,
            scope_label="dyn",
            optimizer_factory=lambda: optimizer,
            target_factory=TargetFactory.singleton(StubTarget(tag=INTERNAL_TAG)),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_config=STUB_LLM_CONFIG,
        )
        await controller.run()
        ctrl_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        # INTERNAL controllable offered because the resolver returned INTERNAL,
        # not some EXTERNAL/empty default.
        assert len(ctrl_events) == 1


# ---------------------------------------------------------------------------
# Two tasks resolved to different scopes gate differently across all surfaces
# ---------------------------------------------------------------------------


def _dispatch_resolver(task: Task[Target]) -> Scope:
    """Resolve EXTERNAL or INTERNAL based on a _TaggedTask's declared want."""
    assert isinstance(task, _TaggedTask)
    return task.want


class TestPerTaskGatingDiffers:
    async def test_controllables_gated_per_task(self) -> None:
        """Two tasks, one EXTERNAL one INTERNAL: each optimizer only receives
        the controllable matching its own resolved scope."""
        ext_task = _TaggedTask("ext", EXTERNAL_SCOPE)
        int_task = _TaggedTask("int", INTERNAL_SCOPE)

        # Capture every optimizer the factory hands out.
        opts: list[_CapturingOptimizer] = []

        def factory() -> _CapturingOptimizer:
            o = _CapturingOptimizer()
            opts.append(o)
            return o

        controller = Controller(
            scope=_dispatch_resolver,
            scope_label="dyn",
            optimizer_factory=factory,
            target_factory=TargetFactory(create=_MultiControllableTarget),
            security_claim=SecurityClaim.from_tasks([ext_task, int_task]),
            llm_config=STUB_LLM_CONFIG,
        )
        await controller.run()
        assert len(opts) == 2
        # Tasks run concurrently; sort the captured optimizers by which tag
        # they saw rather than relying on order.
        names_by_opt = [sorted(c.name for c in o.received_controllables) for o in opts]
        assert ["external_input"] in names_by_opt
        assert ["internal_input"] in names_by_opt

    async def test_observables_gated_per_task(self) -> None:
        opts: list[_CapturingOptimizer] = []

        def factory() -> _CapturingOptimizer:
            o = _CapturingOptimizer()
            opts.append(o)
            return o

        controller = Controller(
            scope=_dispatch_resolver,
            scope_label="dyn",
            optimizer_factory=factory,
            target_factory=TargetFactory(create=_MultiControllableTarget),
            security_claim=SecurityClaim.from_tasks(
                [_TaggedTask("ext", EXTERNAL_SCOPE), _TaggedTask("int", INTERNAL_SCOPE)]
            ),
            llm_config=STUB_LLM_CONFIG,
        )
        await controller.run()
        obs_by_opt = [sorted(o.observable.name for o in c.received_observables) for c in opts]
        assert ["ext_obs"] in obs_by_opt
        assert ["int_obs"] in obs_by_opt

    async def test_trajectory_injection_vs_decline_gated_per_task(self) -> None:
        """The _TwoChannelTarget fires both an EXTERNAL and an INTERNAL event.
        The EXTERNAL task injects only into external_input (declines internal);
        the INTERNAL task injects only into internal_input (declines external)."""
        results_by_scope: dict[str, tuple[list[str], list[str]]] = {}

        controller = Controller(
            scope=_dispatch_resolver,
            scope_label="dyn",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=_TwoChannelTarget),
            security_claim=SecurityClaim.from_tasks(
                [_TaggedTask("ext", EXTERNAL_SCOPE), _TaggedTask("int", INTERNAL_SCOPE)]
            ),
            llm_config=STUB_LLM_CONFIG,
        )
        result = await controller.run()
        for tr in result.task_results:
            snap = tr.runs[0].trajectory.snapshot()
            injected = sorted(
                r.controllable.name for r in snap if isinstance(r, ControllableInjection)
            )
            declined = sorted(
                r.controllable.name for r in snap if isinstance(r, ControllableNoInjection)
            )
            # Key by the resolved write scope recorded on the result.
            key = sorted(t.name for t in tr.scope)[0]
            results_by_scope[key] = (injected, declined)

        assert results_by_scope["external"] == (["external_input"], ["internal_input"])
        assert results_by_scope["internal"] == (["internal_input"], ["external_input"])

    async def test_feedback_sub_scores_gated_per_task(self) -> None:
        """_ScopedScoresTask emits an EXTERNAL and an INTERNAL sub_score; each
        task's RunEndEvent feedback keeps only the in-scope one."""

        # _ScopedScoresTask supplies the scoped sub_scores; carry a `want` tag
        # so the resolver can dispatch on it.
        class _ScopedTagged(_ScopedScoresTask):
            def __init__(self, goal_text: str, want: Scope) -> None:
                super().__init__(goal_text=goal_text)
                self.want = want

        ext_task = _ScopedTagged("ext", EXTERNAL_SCOPE)
        int_task = _ScopedTagged("int", INTERNAL_SCOPE)

        def resolver(task: Task[Target]) -> Scope:
            return task.want  # type: ignore[attr-defined]

        controller = Controller(
            scope=resolver,
            scope_label="dyn",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=StubTarget),
            security_claim=SecurityClaim.from_tasks([ext_task, int_task]),
            llm_config=STUB_LLM_CONFIG,
        )
        result = await controller.run()
        keep_by_scope: dict[str, set[str]] = {}
        for tr in result.task_results:
            entries = tr.runs[0].trajectory.snapshot()
            fb = next(e for e in entries if isinstance(e, RunEndEvent) and e.evaluation is not None)
            key = sorted(t.name for t in tr.scope)[0]
            keep_by_scope[key] = set(fb.evaluation.sub_scores.keys())

        # The EXTERNAL task keeps external_asr, drops internal_leak; vice versa.
        assert keep_by_scope["external"] == {"external_asr"}
        assert keep_by_scope["internal"] == {"internal_leak"}


# ---------------------------------------------------------------------------
# Construction validation
# ---------------------------------------------------------------------------


class TestDynamicScopeValidation:
    def test_callable_scope_without_label_raises(self) -> None:
        with pytest.raises(ValueError, match="scope_label is required"):
            Controller(
                scope=lambda _t: EXTERNAL_SCOPE,
                optimizer_factory=lambda: StubOptimizer(),
                target_factory=TargetFactory.singleton(StubTarget()),
                security_claim=SecurityClaim.from_tasks([StubTask()]),
                llm_config=STUB_LLM_CONFIG,
            )

    def test_callable_scope_with_blank_label_raises(self) -> None:
        """A whitespace-only label is treated as empty."""
        with pytest.raises(ValueError, match="scope_label is required"):
            Controller(
                scope=lambda _t: EXTERNAL_SCOPE,
                scope_label="   ",
                optimizer_factory=lambda: StubOptimizer(),
                target_factory=TargetFactory.singleton(StubTarget()),
                security_claim=SecurityClaim.from_tasks([StubTask()]),
                llm_config=STUB_LLM_CONFIG,
            )

    def test_static_scope_with_label_raises(self) -> None:
        with pytest.raises(ValueError, match="only valid when scope is a callable"):
            Controller(
                scope=EXTERNAL_SCOPE,
                scope_label="oops",
                optimizer_factory=lambda: StubOptimizer(),
                target_factory=TargetFactory.singleton(StubTarget()),
                security_claim=SecurityClaim.from_tasks([StubTask()]),
                llm_config=STUB_LLM_CONFIG,
            )

    def test_callable_scope_with_label_constructs(self) -> None:
        """The valid dynamic-mode construction does not raise."""
        Controller(
            scope=lambda _t: EXTERNAL_SCOPE,
            scope_label="dyn",
            optimizer_factory=lambda: StubOptimizer(),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_config=STUB_LLM_CONFIG,
        )


# ---------------------------------------------------------------------------
# Per-task error / skip containment
# ---------------------------------------------------------------------------


class TestResolverContainment:
    async def test_resolver_empty_scope_is_contained_error(self) -> None:
        """A resolver returning an empty scope (no visibility) makes THAT task a
        contained per-task error; a sibling with a real scope still completes."""

        def resolver(task: Task[Target]) -> Scope:
            if task.goal.description == "bad":
                return frozenset()
            return EXTERNAL_SCOPE

        bad = StubTask(goal_text="bad")
        good = StubTask(goal_text="good")
        controller = Controller(
            scope=resolver,
            scope_label="dyn",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=StubTarget),
            security_claim=SecurityClaim.from_tasks([bad, good]),
            llm_config=STUB_LLM_CONFIG,
        )
        result = await controller.run()
        by_goal = {tr.task.goal.description: tr for tr in result.task_results}
        assert by_goal["bad"].stop_reason == "error"
        assert by_goal["bad"].error is not None
        assert by_goal["bad"].success is False
        # Sibling unaffected.
        assert by_goal["good"].stop_reason == "done"
        assert by_goal["good"].success is True
        # The threat model was not aborted: both tasks present.
        assert len(result.task_results) == 2
        assert result.skipped_tasks == []

    async def test_resolver_generic_exception_is_contained_error(self) -> None:
        """A resolver raising a non-NotApplicable exception becomes a per-task
        error, not a NotApplicable skip and not a crash of the run."""

        def resolver(task: Task[Target]) -> Scope:
            if task.goal.description == "boom":
                raise RuntimeError("resolver exploded")
            return EXTERNAL_SCOPE

        controller = Controller(
            scope=resolver,
            scope_label="dyn",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=StubTarget),
            security_claim=SecurityClaim.from_tasks(
                [StubTask(goal_text="boom"), StubTask(goal_text="fine")]
            ),
            llm_config=STUB_LLM_CONFIG,
        )
        result = await controller.run()
        by_goal = {tr.task.goal.description: tr for tr in result.task_results}
        assert by_goal["boom"].stop_reason == "error"
        assert by_goal["boom"].error is not None
        assert "resolver exploded" in by_goal["boom"].error
        assert "RuntimeError" in by_goal["boom"].error
        assert by_goal["boom"].runs == []
        assert by_goal["fine"].stop_reason == "done"
        assert result.skipped_tasks == []

    async def test_resolver_not_applicable_skips_task(self) -> None:
        """A resolver raising NotApplicable lands the task in skipped_tasks
        (not task_results)."""

        skip_me = StubTask(goal_text="skip")
        keep_me = StubTask(goal_text="keep")

        def resolver(task: Task[Target]) -> Scope:
            if task is skip_me:
                raise NotApplicable("scope resolver opts out")
            return EXTERNAL_SCOPE

        controller = Controller(
            scope=resolver,
            scope_label="dyn",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=StubTarget),
            security_claim=SecurityClaim.from_tasks([skip_me, keep_me]),
            llm_config=STUB_LLM_CONFIG,
        )
        result = await controller.run()
        assert result.skipped_tasks == [skip_me]
        assert [tr.task for tr in result.task_results] == [keep_me]


# ---------------------------------------------------------------------------
# Result fields: TaskResult.scope/read_only and ThreatModelResult.scope_label
# ---------------------------------------------------------------------------


class TestResultScopeFields:
    async def test_dynamic_task_results_record_resolved_scope(self) -> None:
        """Each TaskResult.scope is the per-task resolved write scope, and
        TaskResult.read_only is the run-wide read_only set."""
        ro: Scope = frozenset({ROOT_TAG})

        controller = Controller(
            scope=_dispatch_resolver,
            scope_label="per-tool",
            read_only=ro,
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=StubTarget),
            security_claim=SecurityClaim.from_tasks(
                [_TaggedTask("ext", EXTERNAL_SCOPE), _TaggedTask("int", INTERNAL_SCOPE)]
            ),
            llm_config=STUB_LLM_CONFIG,
        )
        result = await controller.run()
        scopes = {sorted(t.name for t in tr.scope)[0]: tr for tr in result.task_results}
        assert set(scopes) == {"external", "internal"}
        assert scopes["external"].scope == EXTERNAL_SCOPE
        assert scopes["internal"].scope == INTERNAL_SCOPE
        # read_only is the fixed run-wide value on every task.
        assert all(tr.read_only == ro for tr in result.task_results)

    async def test_dynamic_threat_model_result_scope_label_and_empty_scope(self) -> None:
        """In dynamic mode the run-level scope/read_only are empty and the
        scope_label carries the run identity."""
        controller = Controller(
            scope=lambda _t: EXTERNAL_SCOPE,
            scope_label="my-run",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_config=STUB_LLM_CONFIG,
        )
        result = await controller.run()
        assert result.scope_label == "my-run"
        assert result.scope == frozenset()
        assert result.read_only == frozenset()
        # The per-task truth still lives on the TaskResult.
        assert result.task_results[0].scope == EXTERNAL_SCOPE

    async def test_static_mode_task_scope_equals_controller_scope(self) -> None:
        """Static mode is unchanged: every TaskResult.scope equals the
        controller scope and scope_label is None."""
        controller = Controller(
            scope=EXTERNAL_SCOPE,
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=StubTarget),
            security_claim=SecurityClaim.from_tasks(
                [StubTask(goal_text="a"), StubTask(goal_text="b")]
            ),
            llm_config=STUB_LLM_CONFIG,
        )
        result = await controller.run()
        assert result.scope_label is None
        assert result.scope == EXTERNAL_SCOPE
        assert all(tr.scope == EXTERNAL_SCOPE for tr in result.task_results)

    def test_task_result_scope_defaults_empty(self) -> None:
        """The two new fields default to empty frozensets."""
        from superred.core.controller import TaskResult
        from superred.core.types.evaluation import EvaluationResult, Score
        from superred.core.types.llm import LLMUsage

        tr = TaskResult(
            task=StubTask(),
            runs=[],
            best_score=Score(0.0),
            best_evaluation=EvaluationResult(success=False, primary_score=Score(0.0)),
            success=False,
            llm_usage=LLMUsage(),
            stop_reason="done",
        )
        assert tr.scope == frozenset()
        assert tr.read_only == frozenset()

    def test_threat_model_result_scope_label_defaults_none(self) -> None:
        tmr = ThreatModelResult(
            scope=EXTERNAL_SCOPE,
            read_only=frozenset(),
            llm_config=None,
            task_results=[],
        )
        assert tmr.scope_label is None


# ---------------------------------------------------------------------------
# Persistence in dynamic mode
# ---------------------------------------------------------------------------


class TestDynamicScopePersistence:
    async def test_filename_stem_uses_scope_label(self, tmp_path: Path) -> None:
        controller = Controller(
            scope=lambda _t: EXTERNAL_SCOPE,
            scope_label="my-label",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await controller.run()
        assert (tmp_path / "my-label__test-model.json").exists()
        assert (tmp_path / "my-label__test-model").is_dir()

    async def test_claim_summary_records_label_and_empty_scope(self, tmp_path: Path) -> None:
        controller = Controller(
            scope=lambda _t: EXTERNAL_SCOPE,
            scope_label="my-label",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await controller.run()
        payload = json.loads((tmp_path / "my-label__test-model.json").read_text())
        assert payload["scope_label"] == "my-label"
        assert payload["scope"] == []
        assert payload["read_only"] == []
        assert payload["version"] == 2

    async def test_per_task_detail_records_own_resolved_scope(self, tmp_path: Path) -> None:
        """Each detail file records the per-task resolved scope, so two tasks
        at different scopes produce detail files with different scope arrays."""
        controller = Controller(
            scope=_dispatch_resolver,
            scope_label="per-tool",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=StubTarget),
            security_claim=SecurityClaim.from_tasks(
                [_TaggedTask("ext", EXTERNAL_SCOPE), _TaggedTask("int", INTERNAL_SCOPE)]
            ),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await controller.run()
        subfolder = tmp_path / "per-tool__test-model"
        details = sorted(subfolder.glob("*.json"))
        assert len(details) == 2
        scopes_recorded = sorted(json.loads(p.read_text())["scope"] for p in details)
        # One file scoped to external, the other to internal.
        assert scopes_recorded == [["external"], ["internal"]]

    async def test_reused_label_stem_raises_file_exists(self, tmp_path: Path) -> None:
        kwargs = dict(
            scope=lambda _t: EXTERNAL_SCOPE,
            scope_label="dup",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await Controller(**kwargs).run()  # type: ignore[arg-type]
        with pytest.raises(FileExistsError):
            await Controller(**kwargs).run()  # type: ignore[arg-type]
