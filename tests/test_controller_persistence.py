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

from superred.core.controller import Controller, TargetFactory
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
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory.singleton(StubTarget()),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_config=STUB_LLM_CONFIG,
    )
    await controller.run()
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Single threat model -> single file
# ---------------------------------------------------------------------------


async def test_single_threat_model_creates_claim_and_subfolder(tmp_path: Path) -> None:
    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory.singleton(StubTarget()),
        security_claim=SecurityClaim.from_tasks([StubTask(score=0.8, success=True)]),
        llm_config=STUB_LLM_CONFIG,
        results_dir=tmp_path,
    )
    await controller.run()

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
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory.singleton(StubTarget()),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_config=STUB_LLM_CONFIG,
        results_dir=str(tmp_path / "out"),
    )
    await controller.run()
    assert (tmp_path / "out" / "external__test-model.json").exists()
    assert (tmp_path / "out" / "external__test-model").is_dir()


# ---------------------------------------------------------------------------
# Caller-side fanout: one Controller per scope writes one file each
# ---------------------------------------------------------------------------


async def test_two_scopes_via_two_controllers_produce_two_layouts(tmp_path: Path) -> None:
    """Sweeping multiple scopes is the caller's job — two Controllers
    sharing a ``results_dir`` lay out one file/subfolder each."""
    target_factory = TargetFactory.singleton(TwoTagTarget())
    for scope in (EXTERNAL_SCOPE, INTERNAL_SCOPE):
        controller = Controller(
            scope=scope,
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=target_factory,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await controller.run()

    files = sorted(p.name for p in tmp_path.glob("*.json"))
    assert files == [
        "external__test-model.json",
        "internal__test-model.json",
    ]
    assert (tmp_path / "external__test-model").is_dir()
    assert (tmp_path / "internal__test-model").is_dir()


async def test_failed_task_persisted_with_error_stop_reason(tmp_path: Path) -> None:
    """A failing task lands in the threat model's JSON with stop_reason='error'."""
    from superred.core.interfaces.target import Target
    from superred.core.types.evaluation import EvaluationResult
    from superred.core.types.trajectory import Trajectory

    class _FailingEvalTask(StubTask):
        async def evaluate(
            self,
            trajectory: Trajectory,
            target: Target,
        ) -> EvaluationResult:
            raise RuntimeError("evaluation exploded")

    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory.singleton(StubTarget()),
        security_claim=SecurityClaim.from_tasks(
            [_FailingEvalTask(goal_text="bad"), StubTask(goal_text="good")],
        ),
        llm_config=STUB_LLM_CONFIG,
        results_dir=tmp_path,
    )
    await controller.run()

    claim = json.loads((tmp_path / "external__test-model.json").read_text())
    stop_reasons = [tr["stop_reason"] for tr in claim["task_results"]]
    assert stop_reasons == ["error", "done"]
    assert claim["summary"]["n_tasks"] == 2
    assert claim["summary"]["n_success"] == 1

    # The formatted exception is persisted both at the claim-level summary
    # and in the per-task detail file, with a partial trajectory.
    failing_summary = claim["task_results"][0]
    assert failing_summary["error"] is not None
    assert "evaluation exploded" in failing_summary["error"]
    assert "RuntimeError" in failing_summary["error"]
    ok_summary = claim["task_results"][1]
    assert ok_summary["error"] is None

    detail_path = tmp_path / failing_summary["file"]
    detail = json.loads(detail_path.read_text())
    assert detail["error"] is not None
    assert "evaluation exploded" in detail["error"]
    # Partial trajectory preserved as the only RunResult for the failed task.
    assert len(detail["runs"]) == 1
    assert detail["runs"][0]["evaluation"]["primary_score"]["value"] == 0.0


# ---------------------------------------------------------------------------
# Incremental per-task writes
# ---------------------------------------------------------------------------


async def test_per_task_detail_written_before_claim_summary(tmp_path: Path, monkeypatch) -> None:
    """Per-task detail files land on disk as each task finishes — proven by
    making the final claim-summary write fail and verifying the details
    are still readable. Without incremental writes a failure here would
    discard every completed task's trajectory."""
    from superred.core import controller as controller_module

    real_write_claim_summary = controller_module.write_claim_summary

    def boom_claim_summary(*args, **kwargs):
        raise RuntimeError("simulated disk failure on claim summary")

    monkeypatch.setattr(controller_module, "write_claim_summary", boom_claim_summary)

    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory.singleton(StubTarget()),
        security_claim=SecurityClaim.from_tasks(
            [
                StubTask(goal_text="alpha"),
                StubTask(goal_text="beta"),
                StubTask(goal_text="gamma"),
            ]
        ),
        llm_config=STUB_LLM_CONFIG,
        results_dir=tmp_path,
    )
    try:
        await controller.run()
    except RuntimeError:
        pass  # expected — the claim-summary write fails

    # Claim file MUST be absent because its write failed — its absence
    # is the completion-marker signal a post-mortem reads.
    assert not (tmp_path / "external__test-model.json").exists()

    # Per-task detail files for every completed task are on disk anyway.
    subfolder = tmp_path / "external__test-model"
    detail_files = sorted(subfolder.glob("*.json"))
    assert len(detail_files) == 3
    goals = []
    for path in detail_files:
        detail = json.loads(path.read_text())
        goals.append(detail["task"]["goal"])
        # Each detail file is self-contained: scope, llm_config, trajectory.
        assert detail["scope"] == ["external"]
        assert detail["stop_reason"] == "done"
        assert len(detail["runs"]) == 1
    assert goals == ["alpha", "beta", "gamma"]

    # Restoring the real function (defensive — monkeypatch handles cleanup).
    monkeypatch.setattr(controller_module, "write_claim_summary", real_write_claim_summary)


async def test_per_task_detail_visible_to_later_tasks(tmp_path: Path) -> None:
    """With concurrency=1 a later task can read the earlier task's detail
    file from disk — concrete proof that writes happen as each task
    completes, not in a deferred batch at the end."""
    from superred.core.interfaces.target import Target
    from superred.core.types.evaluation import EvaluationResult
    from superred.core.types.trajectory import Trajectory

    sightings: dict[str, bool] = {}

    class _DiskCheckingTask(StubTask):
        """During evaluate, list the subfolder and record whether earlier
        task files are already on disk."""

        def __init__(self, goal_text: str, expected_prior: int) -> None:
            super().__init__(goal_text=goal_text)
            self._expected_prior = expected_prior

        async def evaluate(
            self,
            trajectory: Trajectory,
            target: Target,
        ) -> EvaluationResult:
            subfolder = tmp_path / "external__test-model"
            existing = sorted(subfolder.glob("*.json")) if subfolder.exists() else []
            sightings[self.goal.description] = len(existing) >= self._expected_prior
            return await super().evaluate(trajectory, target)

    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory(create=StubTarget, concurrency=1),
        security_claim=SecurityClaim.from_tasks(
            [
                _DiskCheckingTask("first", expected_prior=0),
                _DiskCheckingTask("second", expected_prior=1),
                _DiskCheckingTask("third", expected_prior=2),
            ]
        ),
        llm_config=STUB_LLM_CONFIG,
        results_dir=tmp_path,
    )
    await controller.run()
    assert sightings == {"first": True, "second": True, "third": True}


# ---------------------------------------------------------------------------
# No tmp leftover on success
# ---------------------------------------------------------------------------


async def test_no_tmp_leftover_after_successful_run(tmp_path: Path) -> None:
    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory.singleton(StubTarget()),
        security_claim=SecurityClaim.from_tasks([StubTask()]),
        llm_config=STUB_LLM_CONFIG,
        results_dir=tmp_path,
    )
    await controller.run()
    assert not list(tmp_path.rglob("*.tmp"))


# ---------------------------------------------------------------------------
# include_feedback=False still produces a valid file
# ---------------------------------------------------------------------------


async def test_include_feedback_false_persists_run_end_with_null_eval(
    tmp_path: Path,
) -> None:
    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory.singleton(StubTarget()),
        security_claim=SecurityClaim.from_tasks([StubTask(score=0.5, success=False)]),
        llm_config=STUB_LLM_CONFIG,
        results_dir=tmp_path,
        include_feedback=False,
    )
    await controller.run()
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


# ---------------------------------------------------------------------------
# Dynamic per-task scope (resolver) persistence
# ---------------------------------------------------------------------------


class TestDynamicScopePersistence:
    """End-to-end persistence when the Controller is given a per-task scope
    *resolver* (``Callable[[Task], Scope]``) plus a ``scope_label``.

    In dynamic mode there is no single concrete run scope: the layout is
    named by the ``scope_label`` and each per-task detail file records the
    scope that was actually resolved (and enforced) for THAT task. The
    claim-level summary then carries an empty top-level ``scope``/``read_only``
    and the ``scope_label`` field instead.
    """

    @staticmethod
    def _per_goal_resolver(task: StubTask) -> Scope:
        """Give the ``ext`` task EXTERNAL scope and the ``int`` task INTERNAL
        scope. The two tasks therefore enforce different scopes within one
        run, which is the whole point of a resolver."""
        if task.goal.description == "ext":
            return EXTERNAL_SCOPE
        return INTERNAL_SCOPE

    @staticmethod
    def _per_goal_read_only(task: StubTask) -> Scope:
        """Give the ``ro_internal`` task an INTERNAL read-only tag and the
        ``ro_none`` task none. With a fixed (non-empty) write ``scope`` both
        tasks still run, but their resolved ``read_only`` differs, which is
        exactly what a per-task ``read_only`` resolver is for."""
        if task.goal.description == "ro_internal":
            return INTERNAL_SCOPE
        return frozenset()

    async def test_scope_label_names_claim_file_and_subfolder(self, tmp_path: Path) -> None:
        """The ``scope_label`` (not any concrete scope) drives both the
        claim filename ``{label}__{model}.json`` and the subfolder
        ``{label}__{model}/``. No single scope could produce these names:
        the two tasks live in EXTERNAL and INTERNAL scopes respectively."""
        controller = Controller(
            scope=self._per_goal_resolver,
            scope_label="mixed-bag",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=TwoTagTarget, concurrency=1),
            security_claim=SecurityClaim.from_tasks(
                [StubTask(goal_text="ext"), StubTask(goal_text="int")],
            ),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await controller.run()

        claim = tmp_path / "mixed-bag__test-model.json"
        subfolder = tmp_path / "mixed-bag__test-model"
        assert claim.exists()
        assert subfolder.is_dir()
        # Neither "external" nor "internal" appears in the stem.
        assert not (tmp_path / "external__test-model.json").exists()
        assert not (tmp_path / "internal__test-model.json").exists()
        detail_files = sorted(subfolder.glob("*.json"))
        assert len(detail_files) == 2

    async def test_per_task_detail_records_own_resolved_scope(self, tmp_path: Path) -> None:
        """Each per-task detail JSON records THAT task's own resolved scope:
        the two files therefore disagree on ``scope`` (one external, one
        internal), which a single run-level scope could never express."""
        controller = Controller(
            scope=self._per_goal_resolver,
            scope_label="mixed-bag",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=TwoTagTarget, concurrency=1),
            security_claim=SecurityClaim.from_tasks(
                [StubTask(goal_text="ext"), StubTask(goal_text="int")],
            ),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await controller.run()

        subfolder = tmp_path / "mixed-bag__test-model"
        # Tasks land in input order: 00001 = ext, 00002 = int.
        details = [json.loads(p.read_text()) for p in sorted(subfolder.glob("*.json"))]
        scopes = [d["scope"] for d in details]
        assert scopes == [["external"], ["internal"]]
        # Goal-to-scope correspondence is exact, not coincidental ordering.
        by_goal = {d["task"]["goal"]: d["scope"] for d in details}
        assert by_goal == {"ext": ["external"], "int": ["internal"]}
        # No read-only tags configured for this run.
        assert all(d["read_only"] == [] for d in details)

    async def test_per_task_detail_records_own_resolved_read_only(self, tmp_path: Path) -> None:
        """A per-task ``read_only`` resolver is persisted per task: each detail
        JSON records THAT task's own resolved ``read_only`` (one ``internal``,
        one empty), so the two files disagree on ``read_only``, which a single
        run-level ``read_only`` could never express. The write ``scope`` is a
        fixed EXTERNAL set, so both tasks run regardless; only ``read_only``
        varies. The claim file is still named by the ``scope_label`` stem."""
        controller = Controller(
            scope=EXTERNAL_SCOPE,
            read_only=self._per_goal_read_only,
            scope_label="ro-mixed",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=TwoTagTarget, concurrency=1),
            security_claim=SecurityClaim.from_tasks(
                [StubTask(goal_text="ro_internal"), StubTask(goal_text="ro_none")],
            ),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await controller.run()

        # The claim layout is named by the scope_label, not any concrete scope.
        claim = tmp_path / "ro-mixed__test-model.json"
        subfolder = tmp_path / "ro-mixed__test-model"
        assert claim.exists()
        assert subfolder.is_dir()

        # Tasks land in input order: 00001 = ro_internal, 00002 = ro_none.
        details = [json.loads(p.read_text()) for p in sorted(subfolder.glob("*.json"))]
        assert len(details) == 2
        read_onlys = [d["read_only"] for d in details]
        # The two detail files disagree on read_only.
        assert read_onlys[0] != read_onlys[1]
        assert read_onlys == [["internal"], []]
        # Goal-to-read_only correspondence is exact, not coincidental ordering.
        by_goal = {d["task"]["goal"]: d["read_only"] for d in details}
        assert by_goal == {"ro_internal": ["internal"], "ro_none": []}
        # Write scope is the fixed EXTERNAL set for both, independent of read_only.
        assert all(d["scope"] == ["external"] for d in details)

    async def test_claim_summary_carries_label_and_empty_scope(self, tmp_path: Path) -> None:
        """The claim-summary JSON records the ``scope_label`` and an EMPTY
        top-level ``scope``/``read_only``: the per-task truth lives in the
        detail files, not the claim summary."""
        controller = Controller(
            scope=self._per_goal_resolver,
            scope_label="mixed-bag",
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=TwoTagTarget, concurrency=1),
            security_claim=SecurityClaim.from_tasks(
                [StubTask(goal_text="ext"), StubTask(goal_text="int")],
            ),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await controller.run()

        claim = json.loads((tmp_path / "mixed-bag__test-model.json").read_text())
        assert claim["scope_label"] == "mixed-bag"
        assert claim["scope"] == []
        assert claim["read_only"] == []
        assert claim["summary"]["n_tasks"] == 2

    async def test_rerun_same_dir_and_label_raises_file_exists(self, tmp_path: Path) -> None:
        """Re-running with the same ``results_dir`` + ``scope_label`` collides
        on the claim file / subfolder and raises ``FileExistsError`` (just as
        a static-scope re-run does)."""

        def make_controller() -> Controller:
            return Controller(
                scope=self._per_goal_resolver,
                scope_label="mixed-bag",
                optimizer_factory=lambda: StubOptimizer(done=True),
                target_factory=TargetFactory(create=TwoTagTarget, concurrency=1),
                security_claim=SecurityClaim.from_tasks(
                    [StubTask(goal_text="ext"), StubTask(goal_text="int")],
                ),
                llm_config=STUB_LLM_CONFIG,
                results_dir=tmp_path,
            )

        await make_controller().run()
        with pytest.raises(FileExistsError):
            await make_controller().run()

    async def test_static_scope_run_unchanged_by_dynamic_feature(self, tmp_path: Path) -> None:
        """Regression: a STATIC-scope run still writes ``external__test-model.json``
        exactly as before, with no ``scope_label`` (``None``) and a concrete
        top-level ``scope``."""
        controller = Controller(
            scope=EXTERNAL_SCOPE,
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=TwoTagTarget, concurrency=1),
            security_claim=SecurityClaim.from_tasks([StubTask(goal_text="ext")]),
            llm_config=STUB_LLM_CONFIG,
            results_dir=tmp_path,
        )
        await controller.run()

        claim_path = tmp_path / "external__test-model.json"
        assert claim_path.exists()
        assert (tmp_path / "external__test-model").is_dir()
        claim = json.loads(claim_path.read_text())
        assert claim["scope"] == ["external"]
        assert claim["scope_label"] is None
        detail = json.loads(next((tmp_path / "external__test-model").glob("*.json")).read_text())
        assert detail["scope"] == ["external"]


async def test_detail_write_failure_is_contained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing per-task detail write is logged and swallowed; the run still completes."""
    import superred.core.controller as controller_mod

    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(controller_mod, "write_task_detail", _boom)
    controller = Controller(
        scope=EXTERNAL_SCOPE,
        optimizer_factory=lambda: StubOptimizer(done=True),
        target_factory=TargetFactory(create=lambda: StubTarget(tag=EXTERNAL_TAG)),
        security_claim=SecurityClaim.from_tasks([StubTask(goal_text="g")]),
        llm_config=STUB_LLM_CONFIG,
        results_dir=str(tmp_path),
    )
    result = await controller.run()
    # The detail-write failure was contained: the task still completed and is in
    # the result, and the claim-summary completion marker was still written.
    assert len(result.task_results) == 1
    assert result.task_results[0].stop_reason == "done"
    assert (tmp_path / "external__test-model.json").exists()
