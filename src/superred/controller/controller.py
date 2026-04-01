"""Controller — core evaluation loop that wires channels, targets, and optimizers."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from typing import Sequence

from superred.interfaces.target import Target
from superred.interfaces.task import Task
from superred.interfaces.optimizer import Optimizer
from superred.types import Controllable, ObservableValue, Trajectory
from superred.types.security import ThreatModel
from superred.types.budget import HierarchicalBudget
from superred.types.claim import ClaimPredicate, ContextSnapshot
from superred.channels.channel import channel
from superred.channels.middleware import compose, trace_recorder, threat_model_filter
from superred.controller.results import RunResult, TaskResult

logger = logging.getLogger("superred.controller")


class Controller:
    """Drives the target+optimizer evaluation loop.

    The controller wires channels, runs the concurrent target+optimizer loop,
    and collects results.  Budget is tracked at the iteration (run) level by
    the controller; per-event budget enforcement is handled separately by
    middleware when needed.
    """

    def __init__(
        self,
        target: Target,
        task: Task,
        optimizer: Optimizer,
        threat_model: ThreatModel,
        budget: HierarchicalBudget,
        claim_predicates: Sequence[ClaimPredicate] = (),
    ) -> None:
        self._target = target
        self._task = task
        self._optimizer = optimizer
        self._threat_model = threat_model
        self._budget = budget
        self._claim_predicates = list(claim_predicates)

    async def run(self) -> TaskResult:
        """Execute the full evaluation loop and return collected results."""
        target = self._target
        task = self._task
        optimizer = self._optimizer
        tm = self._threat_model
        budget = self._budget

        await target.setup()
        try:
            config = await task.configure(target)
            observables = await target.get_observables()
            all_controllables = target.controllable_specs()

            # Filter controllables and observables by threat model
            filtered_specs = [
                s for s in all_controllables
                if s.security_domain.name in tm.controllables
            ]
            filtered_obs = [
                o for o in observables
                if o.observable.security_domain.name in tm.observables
            ]
            controllables = [Controllable(spec=s) for s in filtered_specs]

            await optimizer.initialize(
                task.goal, controllables, filtered_obs, budget
            )

            result = TaskResult(task_goal=task.goal)

            while not budget.exhausted:
                trajectory = Trajectory()

                # Fresh channels per iteration
                event_ch = channel()
                response_ch = channel()

                # Wire middleware stack onto event channel.
                # trace_recorder records events to the trajectory.
                # threat_model_filter drops events outside the threat model scope.
                # Budget counting is handled by the controller at the run level.
                stack = compose(
                    trace_recorder(trajectory),
                    threat_model_filter(tm),
                )
                filtered_event_ch = stack(event_ch)

                optimizer._on_run_start(trajectory)
                await optimizer.pre_run()

                # Spawn optimizer loop as concurrent task
                loop_task = asyncio.create_task(
                    optimizer._run_loop(
                        filtered_event_ch.receiver,
                        response_ch.sender,
                    )
                )

                try:
                    await target.run(event_ch.sender, response_ch.receiver)
                except Exception as e:
                    logger.error("Target error: %s", e)
                finally:
                    # Close the event sender so the middleware pipe terminates
                    # and the optimizer loop exits gracefully.
                    event_ch.sender.close()
                    await loop_task
                    response_ch.sender.close()

                # Archive trajectory and call post-run hooks
                optimizer._on_run_end()
                post_run_signal = await optimizer.post_run()

                evaluation = await task.evaluate(trajectory, target)

                # Evaluate claim predicates
                claim_verdicts = []
                if self._claim_predicates:
                    snapshot = ContextSnapshot(
                        goal=task.goal,
                        trajectory_entries=trajectory.snapshot(),
                        task_config=config,
                    )
                    oracle = task.oracle_bundle()
                    for pred in self._claim_predicates:
                        claim_verdicts.append(pred(snapshot, oracle))

                # Record one iteration against the budget
                budget.record(iterations=1)

                run_result = RunResult(
                    trajectory=trajectory,
                    evaluation=evaluation,
                    claim_verdicts=claim_verdicts,
                    budget_used=replace(budget.usage),
                    threat_model=tm,
                    optimizer_metadata=optimizer.get_metadata(),
                )
                result.runs.append(run_result)

                if post_run_signal is not None or budget.exhausted:
                    break

        finally:
            try:
                await optimizer.teardown()
            finally:
                await target.teardown()

        return result
