"""Manual mutation tests: each test targets a specific mutation that could
survive if the test suite were weak. These are the mutations that matter most.

Naming: test_<module>_<mutation_description>

These tests are designed to kill common mutant patterns:
- Boundary changes: `<` to `<=`, `>=` to `>`, `is` to `is not`
- Return value changes: `True` to `False`, `None` to value
- Condition negation: `not x` to `x`, `if x` to `if not x`
- Operator changes: `and` to `or`, `+` to `-`
- Off-by-one: `range(n)` to `range(n-1)`
"""

from __future__ import annotations

import asyncio

import pytest

from superred.core.channel import EventChannel, EventEnvelope
from superred.core.controller import Controller
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.middleware import compose, security_domain_filter
from superred.core.types.controllable import Controllable, ControllableSpec
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.event import (
    ControllableInjection,
    ControllablePostCallEvent,
    ControllablePreCallEvent,
    Event,
    EventResponse,
    NoModification,
    RunEndEvent,
    RunEndResponse,
)
from superred.core.types.security_domain import SecurityDomain, SecurityDomainTag
from superred.core.types.trajectory import MODEL_REQUEST, Trajectory, TrajectoryEntry

from .conftest import (
    EXTERNAL_TAG,
    INTERNAL_TAG,
    ROOT_TAG,
    StubOptimizer,
    StubTarget,
    StubTask,
)

# ---------------------------------------------------------------------------
# SecurityDomainTag.includes — kills mutations in the traversal loop
# ---------------------------------------------------------------------------


class TestIncludesMutations:
    def test_includes_stops_at_self_not_parent(self) -> None:
        """Kills: `current is self` mutated to `current is self.parent`."""
        a = SecurityDomainTag("a")
        assert a.includes(a) is True

    def test_includes_walks_full_chain(self) -> None:
        """Kills: `current = current.parent` mutated to `current = None`
        (would fail to find ancestor beyond immediate parent)."""
        root = SecurityDomainTag("root")
        mid = SecurityDomainTag("mid", parent=root)
        leaf = SecurityDomainTag("leaf", parent=mid)
        assert root.includes(leaf) is True

    def test_includes_returns_false_not_true_for_unrelated(self) -> None:
        """Kills: final `return False` mutated to `return True`."""
        a = SecurityDomainTag("a")
        b = SecurityDomainTag("b")
        assert a.includes(b) is False

    def test_includes_returns_true_not_false_for_match(self) -> None:
        """Kills: `return True` inside loop mutated to `return False`."""
        a = SecurityDomainTag("a")
        b = SecurityDomainTag("b", parent=a)
        assert a.includes(b) is True


# ---------------------------------------------------------------------------
# SecurityDomain construction — kills validation mutations
# ---------------------------------------------------------------------------


class TestSecurityDomainConstructionMutations:
    def test_duplicate_check_uses_in_not_not_in(self) -> None:
        """Kills: `if tag.name in tag_map` mutated to `if tag.name not in tag_map`."""
        a = SecurityDomainTag("dup")
        b = SecurityDomainTag("dup")
        with pytest.raises(ValueError, match="Duplicate"):
            SecurityDomain([a, b])

    def test_orphan_check_uses_not_in(self) -> None:
        """Kills: `tag.parent.name not in tag_map` mutated to `in tag_map`."""
        outside = SecurityDomainTag("outside")
        child = SecurityDomainTag("child", parent=outside)
        with pytest.raises(ValueError):
            SecurityDomain([child])

    def test_parent_none_check(self) -> None:
        """Kills: `if tag.parent is not None` mutated to `is None`."""
        root = SecurityDomainTag("root")
        child = SecurityDomainTag("child", parent=root)
        # Must NOT raise when parent IS in the domain
        domain = SecurityDomain([root, child])
        assert len(domain.roots) == 1


# ---------------------------------------------------------------------------
# SecurityDomain immutability — kills setattr/delattr mutations
# ---------------------------------------------------------------------------


class TestSecurityDomainImmutabilityMutations:
    def test_setattr_message(self) -> None:
        """Kills: `raise AttributeError(...)` mutated to `pass`."""
        domain = SecurityDomain([SecurityDomainTag("a")])
        with pytest.raises(AttributeError):
            domain.x = 1  # type: ignore[attr-defined]

    def test_delattr_message(self) -> None:
        """Kills: `raise AttributeError(...)` mutated to `pass`."""
        domain = SecurityDomain([SecurityDomainTag("a")])
        with pytest.raises(AttributeError):
            del domain._tags  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Trajectory — kills emit/drain/close mutations
# ---------------------------------------------------------------------------


class TestTrajectoryMutations:
    def test_emit_checks_closed_not_open(self) -> None:
        """Kills: `if self._closed` mutated to `if not self._closed`."""
        t = Trajectory()
        entry = TrajectoryEntry(entry_type=MODEL_REQUEST, content="x")
        t.emit(entry)  # should work when open
        t.close()
        with pytest.raises(RuntimeError):
            t.emit(entry)  # should fail when closed

    def test_drain_advances_cursor(self) -> None:
        """Kills: `self._drain_cursor = len(self._entries)` mutated to
        `self._drain_cursor = 0` or removed entirely."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        first = t.drain()
        assert len(first) == 1
        second = t.drain()
        assert len(second) == 0  # cursor must have advanced

    def test_drain_uses_cursor_not_zero(self) -> None:
        """Kills: `self._entries[self._drain_cursor:]` mutated to
        `self._entries[0:]`."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        t.drain()  # advance cursor
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="b"))
        result = t.drain()
        assert len(result) == 1
        assert result[0].content == "b"

    def test_snapshot_does_not_advance_cursor(self) -> None:
        """Kills: snapshot() accidentally using drain cursor logic."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        t.snapshot()
        assert len(t.drain()) == 1  # drain should still see it


# ---------------------------------------------------------------------------
# EventChannel — kills close/respond guard mutations
# ---------------------------------------------------------------------------


class TestChannelMutations:
    async def test_double_respond_guard(self) -> None:
        """Kills: `if self._responded` mutated to `if not self._responded`."""
        loop = asyncio.get_running_loop()
        event = Event()
        future: asyncio.Future[EventResponse] = loop.create_future()
        envelope = EventEnvelope(event=event, future=future, loop=loop)
        envelope.respond(EventResponse(event=event))
        with pytest.raises(RuntimeError, match="already responded"):
            envelope.respond(EventResponse(event=event))

    async def test_close_idempotency_guard(self) -> None:
        """Kills: `if self._closed: return` mutated to `if not self._closed: return`."""
        channel = EventChannel()
        channel.close()
        channel.close()  # must not raise or put double sentinel
        # Only one None on queue
        result = await channel.receive()
        assert result is None

    async def test_close_puts_sentinel(self) -> None:
        """Kills: `self._queue.put_nowait(None)` removed or replaced."""
        channel = EventChannel()
        channel.close()
        result = await channel.receive()
        assert result is None


# ---------------------------------------------------------------------------
# Middleware — kills filter condition mutations
# ---------------------------------------------------------------------------


class TestMiddlewareMutations:
    async def test_filter_checks_includes_not_excludes(self) -> None:
        """Kills: `not scope.includes(...)` mutated to `scope.includes(...)`."""
        async def handler(event: Event) -> EventResponse:
            return ControllableInjection(event=event, value="injected")

        filtered = security_domain_filter(EXTERNAL_TAG)(handler)

        # INTERNAL is NOT included by EXTERNAL — must be blocked
        c = Controllable(spec=ControllableSpec(name="c", security_domain=INTERNAL_TAG))
        event = ControllablePreCallEvent(controllable=c, request="hi")
        response = await filtered(event)
        assert isinstance(response, NoModification)

    async def test_filter_forwards_in_scope_not_blocks(self) -> None:
        """Kills: in-scope path returning NoModification instead of handler result."""
        async def handler(event: Event) -> EventResponse:
            return ControllableInjection(event=event, value="injected")

        filtered = security_domain_filter(ROOT_TAG)(handler)

        c = Controllable(spec=ControllableSpec(name="c", security_domain=EXTERNAL_TAG))
        event = ControllablePreCallEvent(controllable=c, request="hi")
        response = await filtered(event)
        assert isinstance(response, ControllableInjection)
        assert response.value == "injected"

    async def test_filter_checks_post_call_events_too(self) -> None:
        """Kills: isinstance check only matching PreCall, not PostCall."""
        async def handler(event: Event) -> EventResponse:
            return EventResponse(event=event)

        filtered = security_domain_filter(EXTERNAL_TAG)(handler)

        c = Controllable(spec=ControllableSpec(name="c", security_domain=INTERNAL_TAG))
        event = ControllablePostCallEvent(controllable=c, request="hi", answer="bye")
        response = await filtered(event)
        assert isinstance(response, NoModification)

    async def test_compose_reverses_order(self) -> None:
        """Kills: `reversed(middlewares)` mutated to `middlewares`."""
        order: list[str] = []

        def make_mw(name: str) -> object:
            def mw(handler: object) -> object:
                async def wrapped(event: Event) -> EventResponse:
                    order.append(name)
                    return await handler(event)  # type: ignore[misc]
                return wrapped
            return mw

        async def inner(event: Event) -> EventResponse:
            return EventResponse(event=event)

        wrapped = compose(make_mw("outer"), make_mw("inner"))(inner)  # type: ignore[arg-type]
        await wrapped(Event())  # type: ignore[misc]
        assert order == ["outer", "inner"]


# ---------------------------------------------------------------------------
# SecurityClaim — kills factory/iteration mutations
# ---------------------------------------------------------------------------


class TestSecurityClaimMutations:
    def test_from_tasks_copies_list(self) -> None:
        """Kills: `list(tasks)` mutated to `tasks` (shared reference)."""
        t = StubTask(goal_text="a")
        original = [t]
        claim = SecurityClaim.from_tasks(original)
        original.clear()
        assert list(claim) == [t]

    def test_from_claims_chains_all(self) -> None:
        """Kills: `yield from claim` mutated to `yield claim` or `return`."""
        t1 = StubTask(goal_text="a")
        t2 = StubTask(goal_text="b")
        c1 = SecurityClaim.from_tasks([t1])
        c2 = SecurityClaim.from_tasks([t2])
        combined = SecurityClaim.from_claims([c1, c2])
        result = list(combined)
        assert len(result) == 2
        assert result[0] is t1
        assert result[1] is t2

    def test_from_tasks_empty_guard(self) -> None:
        """Kills: `if not tasks` mutated to `if tasks`."""
        with pytest.raises(ValueError):
            SecurityClaim.from_tasks([])

    def test_from_claims_empty_guard(self) -> None:
        """Kills: `if not claims` mutated to `if claims`."""
        with pytest.raises(ValueError):
            SecurityClaim.from_claims([])


# ---------------------------------------------------------------------------
# Controller run loop — kills score tracking and done signal mutations
# ---------------------------------------------------------------------------


class TestControllerRunMutations:
    async def test_done_true_stops_loop(self) -> None:
        """Kills: `if done: break` removed or negated."""
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
            max_runs_per_task=10,
        )
        result = await controller.run()
        assert len(result.task_results[0].runs) == 1  # stopped at 1, not 10

    async def test_done_false_continues_to_max(self) -> None:
        """Kills: `done=True` default or `max_runs_per_task` off-by-one."""
        optimizer = StubOptimizer(done=False)
        controller = Controller(
            optimizer=optimizer,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
            max_runs_per_task=3,
        )
        result = await controller.run()
        assert len(result.task_results[0].runs) == 3

    async def test_success_tracked_across_runs(self) -> None:
        """Kills: `if evaluation.success: success = True` removed or
        `success` initialized to True."""
        optimizer = StubOptimizer(done=False)
        controller = Controller(
            optimizer=optimizer,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask(success=False)]),
            security_domain_tag=EXTERNAL_TAG,
            max_runs_per_task=2,
        )
        result = await controller.run()
        assert result.task_results[0].success is False

    async def test_best_score_uses_greater_than(self) -> None:
        """Kills: `>` mutated to `>=` or `<` in score comparison."""
        run_count = 0

        class ScoreOptimizer(StubOptimizer):
            async def on_event(self, event: Event) -> EventResponse:
                nonlocal run_count
                if isinstance(event, RunEndEvent):
                    run_count += 1
                    return RunEndResponse(event=event, done=run_count >= 2)
                return await super().on_event(event)

        # First run returns 0.8, second returns 0.5
        scores = iter([0.8, 0.5])

        class ScoredTask(StubTask):
            async def evaluate(self, trajectory: Trajectory, target: object) -> EvaluationResult:
                return EvaluationResult(
                    success=False, primary_score=Score(value=next(scores))
                )

        controller = Controller(
            optimizer=ScoreOptimizer(done=False),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([ScoredTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        # Best should be 0.8 (first run), not 0.5 (last run)
        assert result.task_results[0].best_score.value == 0.8

    async def test_best_score_tie_keeps_first(self) -> None:
        """Kills: `>` mutated to `>=` — on a tie, the first evaluation wins."""
        from .conftest import CountingOptimizer

        evals = iter([
            EvaluationResult(success=False, primary_score=Score(0.5), rationale="first"),
            EvaluationResult(success=False, primary_score=Score(0.5), rationale="second"),
        ])

        class TiedTask(StubTask):
            async def evaluate(self, trajectory: Trajectory, target: object) -> EvaluationResult:
                return next(evals)

        controller = Controller(
            optimizer=CountingOptimizer(stop_after=2),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([TiedTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        assert result.task_results[0].best_evaluation.rationale == "first"

    async def test_trajectory_close_called(self) -> None:
        """Kills: `trajectory.close()` removed from _run_single."""
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        traj = result.task_results[0].runs[0].trajectory
        # Trajectory must be closed — emitting should raise
        with pytest.raises(RuntimeError, match="closed"):
            traj.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="x"))

    async def test_initialize_called(self) -> None:
        """Kills: `optimizer.initialize()` call removed."""
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        assert optimizer.initialized is True

    async def test_max_runs_validation(self) -> None:
        """Kills: `max_runs_per_task < 1` check removed."""
        with pytest.raises(ValueError):
            Controller(
                optimizer=StubOptimizer(),
                target=StubTarget(),
                security_claim=SecurityClaim.from_tasks([StubTask()]),
                security_domain_tag=EXTERNAL_TAG,
                max_runs_per_task=0,
            )

    async def test_initialize_receives_real_controllables(self) -> None:
        """Kills mutant 25/26: `controllables = None` / `observables = None`.
        Verifies optimizer.initialize() receives actual target data."""
        received_controllables = None
        received_observables = None

        class CapturingOptimizer(StubOptimizer):
            async def initialize(
                self, goal: object, controllables: object, observables: object,
            ) -> None:
                nonlocal received_controllables, received_observables
                received_controllables = controllables
                received_observables = observables

        optimizer = CapturingOptimizer(done=True)
        target = StubTarget()
        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()

        assert received_controllables is not None
        assert isinstance(received_controllables, list)
        assert len(received_controllables) == 1
        assert received_observables is not None
        assert isinstance(received_observables, list)


# ---------------------------------------------------------------------------
# RunEndResponse default — kills mutant 160
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# MC/DC: controller.py:225 — `best_score is None or value > best_score.value`
# Sub-conditions: A = (best_score is None), B = (value > best_score.value)
# MC/DC requires: A alone flips outcome, B alone flips outcome.
# ---------------------------------------------------------------------------


class TestBestScoreMCDC:
    async def test_first_run_best_score_is_none(self) -> None:
        """MC/DC: A=True makes condition True regardless of B.
        On first run, best_score is None, so the score is always accepted."""
        controller = Controller(
            optimizer=StubOptimizer(done=True), target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask(score=0.1)]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        assert result.task_results[0].best_score.value == 0.1

    async def test_higher_score_replaces(self) -> None:
        """MC/DC: A=False, B=True — higher score replaces."""
        from .conftest import CountingOptimizer

        scores = iter([0.3, 0.7])

        class S(StubTask):
            async def evaluate(self, traj: Trajectory, t: object) -> EvaluationResult:
                return EvaluationResult(success=False, primary_score=Score(next(scores)))

        controller = Controller(
            optimizer=CountingOptimizer(stop_after=2), target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([S()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        assert result.task_results[0].best_score.value == 0.7

    async def test_lower_score_does_not_replace(self) -> None:
        """MC/DC: A=False, B=False — lower score does NOT replace."""
        from .conftest import CountingOptimizer

        scores = iter([0.9, 0.1])

        class S(StubTask):
            async def evaluate(self, traj: Trajectory, t: object) -> EvaluationResult:
                return EvaluationResult(success=False, primary_score=Score(next(scores)))

        controller = Controller(
            optimizer=CountingOptimizer(stop_after=2), target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([S()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        assert result.task_results[0].best_score.value == 0.9


# ---------------------------------------------------------------------------
# MC/DC: security_domain.py:68 — `parent is not None and name not in tag_map`
# Already covered by TestSecurityDomainValidationMutations:
#   test_parent_is_none_check (A=False → condition False)
#   test_orphan_check_uses_not_in (A=True, B=True → condition True)
#   test_parent_in_domain_check (A=True, B=False → condition False)
# MC/DC: security_domain.py:104 — same pattern, tested via
# distinct_combinations property tests which exercise both root and child nodes.
# ---------------------------------------------------------------------------


class TestRunEndResponseDefault:
    def test_done_defaults_to_false(self) -> None:
        """Kills mutant 160: `done: bool = True` instead of `done: bool = False`."""
        from superred.core.types.event import RunEndResponse

        e = Event()
        r = RunEndResponse(event=e)
        assert r.done is False


# ---------------------------------------------------------------------------
# SecurityDomain validation — kills mutants 233, 236, 237, 238
# ---------------------------------------------------------------------------


class TestSecurityDomainValidationMutations:
    def test_duplicate_allowed_on_invert(self) -> None:
        """Kills mutant 233: `in tag_map` -> `not in tag_map`.
        With the mutation, duplicates would pass and uniques would raise."""
        a = SecurityDomainTag("a")
        b = SecurityDomainTag("b")
        # Unique names must NOT raise
        SecurityDomain([a, b])
        # Duplicate names MUST raise
        with pytest.raises(ValueError, match="Duplicate"):
            SecurityDomain([a, SecurityDomainTag("a")])

    def test_parent_is_none_check(self) -> None:
        """Kills mutant 236: `is not None` -> `is None`.
        With the mutation, root tags (parent=None) would trigger
        None.name access and crash."""
        root = SecurityDomainTag("root")
        # Root tag with parent=None must NOT crash
        domain = SecurityDomain([root])
        assert len(domain.roots) == 1

    def test_parent_in_domain_check(self) -> None:
        """Kills mutant 237: `not in tag_map` -> `in tag_map`.
        With the mutation, valid parent refs would be rejected."""
        root = SecurityDomainTag("root")
        child = SecurityDomainTag("child", parent=root)
        domain = SecurityDomain([root, child])
        assert len(domain.roots) == 1

    def test_and_vs_or_in_parent_check(self) -> None:
        """Kills mutant 238: `and` -> `or`.
        With the mutation, root tags (parent=None) would fall through
        to tag.parent.name which crashes on NoneType."""
        root = SecurityDomainTag("root")
        child = SecurityDomainTag("child", parent=root)
        # Must handle both root (parent=None) and child (parent exists)
        domain = SecurityDomain([root, child])
        assert len(domain.roots) == 1


# ---------------------------------------------------------------------------
# EventChannel loop capture — kills mutants 108, 109
# ---------------------------------------------------------------------------


class TestChannelLoopCaptureMutations:
    async def test_loop_capture_on_first_send(self) -> None:
        """Kills mutant 108/109: loop capture inversion/nullification.
        Note: these are equivalent mutants — close() falls back to put_nowait
        when _loop is None, so single-threaded tests can't detect the mutation."""
        channel = EventChannel()
        count = 0

        async def receiver() -> None:
            nonlocal count
            async for envelope in channel:
                count += 1
                envelope.respond(EventResponse(event=envelope.event))

        recv_task = asyncio.create_task(receiver())
        await channel.send(Event())
        await channel.send(Event())
        channel.close()
        await recv_task
        assert count == 2


# ---------------------------------------------------------------------------
# SecurityClaim._claims = None — kills mutant 316
# ---------------------------------------------------------------------------


class TestSecurityClaimFromTasksClaimsField:
    def test_from_tasks_sets_claims_to_none(self) -> None:
        """Kills mutant 316: `claim._claims = None` -> `claim._claims = ''`.
        With the mutation, __iter__ would fall through the _tasks check
        and hit the claims branch with an empty string."""
        t = StubTask(goal_text="a")
        claim = SecurityClaim.from_tasks([t])
        # Must iterate via _tasks path, not _claims
        result = list(claim)
        assert result == [t]
        # Iterate again — must still work (re-iterable)
        assert list(claim) == [t]
