# Controller

The controller is the main orchestrator for red-teaming evaluations. It wires together an optimizer, target, and security claim, managing the full lifecycle with channel-based communication.

## Construction

```python
target = MyTarget(api_key="sk-...")  # manual values at construction
optimizer = MyOptimizer()
claim = SecurityClaim.from_tasks([task_a, task_b])

controller = Controller(
    optimizer=optimizer,
    target=target,
    security_claim=claim,
    security_domain_tag=external_tag,
    max_runs_per_task=100,  # safety limit, default 100
)

result = asyncio.run(controller.run())
```

The controller does not create an asyncio event loop — the caller provides it via `asyncio.run()` or an existing loop.

## Run lifecycle

`await controller.run() -> ControllerResult`:

1. **Per task** (from security claim):
   - `task.configure_target(target)` — if `NotApplicable`, skip task.
   - `optimizer.initialize(goal, filtered_controllables, filtered_observables)` — only controllables and observables within the security domain scope are passed.
   - Create `EventChannel`, launch `optimizer.run(channel)` as concurrent `asyncio.Task`.
   - **Run loop** (until optimizer signals done or `max_runs_per_task`):
     - Create `Trajectory(filtered_scope=scope)`, access `trajectory.filtered` for optimizer's view.
     - Send `RunStartEvent(filtered_trajectory)` through channel — optimizer gets filtered view.
     - `target.run(emit, send_event)` — target emits `LogEvent` instances via `emit(event)`; `send_event` bridges to channel with security domain filtering. The `trajectory_recorder` middleware records all events and responses directly to the trajectory.
     - Send `RunEndEvent(filtered_trajectory)` through channel — check `RunEndResponse.done`.
     - `task.evaluate(trajectory, target)` — returns `EvaluationResult`. Controller filters `sub_scores` by scope (keeping only in-scope scores), emits a `FeedbackEvent(evaluation=filtered_eval, security_domain=scope)` to the trajectory, then closes it.
     - `target.cleanup()` — reset target state for next run.
     - Track best score, success across runs.
     - If `done=True`, break.
   - Close channel, await optimizer task.
   - Collect `TaskResult`.
2. **Teardown** (in `finally` — always runs, even on exception): `optimizer.teardown()`, `target.teardown()`.
3. **Summary**: Print human-readable results to stdout.
4. **Return** `ControllerResult`.

### Internal structure

- `_run_task(task)` — manages the full lifecycle for one task: configure, initialize optimizer, build middleware stack, run loop, collect results.
- `_run_single(task, channel, send_event, run_number)` — executes one iteration: RunStartEvent → target.run → RunEndEvent → evaluate → feedback → close trajectory. Returns `(trajectory, evaluation, done)`.

The `send_event` callback passed to `target.run` is built by composing middleware onto `channel.send`:
```python
send_event = compose(
    security_domain_filter(tag),
    trajectory_recorder(trajectory),
)(channel.send)
```

Users can add custom middleware (logging, tracing, budget enforcement) by extending the composition.

## Security domain filtering

The controller enforces the security domain scope across **all optimizer inputs**:

1. **Controllables**: Filtered with `scope.includes(c.spec.security_domain)` before `optimizer.initialize()`. Out-of-scope controllables are never exposed to the optimizer.
2. **Observables**: Filtered with `scope.includes(o.observable.security_domain)` before `optimizer.initialize()`. Out-of-scope observables are never exposed to the optimizer.
3. **Events**: `ControllablePreCallEvent` and `ControllablePostCallEvent` for out-of-scope controllables are answered with `ControllableNoInjection` without reaching the optimizer. Implemented as the `security_domain_filter` middleware composed onto `channel.send`.
4. **Trajectory**: The optimizer receives a `FilteredTrajectory` (via `RunStartEvent`/`RunEndEvent`) that only exposes items within the security domain scope.
5. **Feedback**: Each `Score` in the `EvaluationResult` carries a `security_domain`. The controller filters `sub_scores` to only include in-scope scores before emitting a `FeedbackEvent` to the trajectory. `primary_score`, `success`, and `rationale` are always included (the optimizer needs the main optimization signal).

This allows testing specific security boundaries — scoping to `external` tests only external-facing surfaces, while scoping to `root` tests everything.

## Unified trajectory as event log

There is no separate event log. The `trajectory_recorder` middleware records all events and responses directly into the trajectory as `Event | EventResponse` objects:

- **Controllable events** — `ControllablePreCallEvent`, `ControllablePostCallEvent`.
- **Controllable responses** — `ControllableInjection`, `ControllableNoInjection`.
- **Log events** — `LogEvent` emitted by the target (model requests, model responses, etc.).
- **Feedback** — `FeedbackEvent` emitted by the controller after evaluation.

The trajectory IS the event log. Lifecycle events (`RunStartEvent`, `RunEndEvent`) are NOT persisted to the trajectory — they carry no additional information and always appear at fixed positions. To inspect events and responses for a run, query the trajectory items by type.

## Result types

### RunResult (frozen)

One target execution + evaluation:
- `trajectory: Trajectory` — the run trajectory.
- `evaluation: EvaluationResult` — the evaluation result for this run.

### TaskResult (frozen)

All runs for one task:
- `task: Task[Target]` — the task that was evaluated.
- `runs: list[RunResult]` — all run results, in order.
- `best_score: Score` — highest primary score across all runs.
- `best_evaluation: EvaluationResult` — the evaluation that produced the best score.
- `success: bool` — whether any run achieved the adversarial goal.

### ControllerResult (frozen)

The full evaluation:
- `task_results: list[TaskResult]` — results for each evaluated task.
- `skipped_tasks: list[Task[Target]]` — tasks that raised `NotApplicable`.

## Design decisions

- **Concrete class, not ABC**: There is one orchestration logic.
- **Channel-based**: Controller creates an `EventChannel` per task. Target's `send_event` callback bridges to `channel.send()` with filtering. Optimizer pulls from channel in `run()`.
- **Multi-run loop**: Runs until optimizer signals `RunEndResponse(done=True)` or `max_runs_per_task` safety limit. `max_runs_per_task` is validated >= 1 at construction.
- **Concurrent optimizer**: `optimizer.run(channel)` is launched as an `asyncio.Task`. The optimizer stays alive across all runs for a task — one channel, one optimizer task per task.
- **Cleanup after each run**: `target.cleanup()` is called after each evaluation to reset state.
- **Exception-safe teardown**: `optimizer.teardown()` and `target.teardown()` are called in a `finally` block, ensuring cleanup even if a task raises an unexpected exception.
- **Exception-safe channel shutdown**: If `target.run()` or `task.evaluate()` raises, the `finally` block in `_run_task` closes the channel and awaits the optimizer task, preventing deadlock.
- **Unified trajectory**: Events and responses are recorded directly to the trajectory via the `trajectory_recorder` middleware. No separate event log — the trajectory is the single source of truth.
- **CLI-ready**: Constructor takes plain parameters. A future CLI module can parse config, instantiate components, call `asyncio.run(controller.run())`. `ControllerResult` provides structured output for programmatic use.
