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
   - `optimizer.initialize(goal, controllables, observables)`.
   - Create `EventChannel`, launch `optimizer.run(channel)` as concurrent `asyncio.Task`.
   - **Run loop** (until optimizer signals done or `max_runs_per_task`):
     - Send `RunStartEvent(trajectory)` through channel.
     - `target.run(trajectory, send_event)` — `send_event` bridges to channel with security domain filtering.
     - Send `RunEndEvent(trajectory)` through channel — check `RunEndResponse.done`.
     - `task.evaluate(trajectory, target)` — append `FeedbackResult` to trajectory, close it.
     - `target.cleanup()` — reset target state for next run.
     - Track best score, success across runs.
     - If `done=True`, break.
   - Close channel, await optimizer task.
   - Collect `TaskResult`.
2. **Summary**: Print human-readable results to stdout.
3. **Teardown**: `optimizer.teardown()`, `target.teardown()`.
4. **Return** `ControllerResult`.

### Internal structure

- `_run_task(task)` — manages the full lifecycle for one task: configure, initialize optimizer, run loop, collect results.
- `_run_single(task, channel, run_number)` — executes one iteration: RunStartEvent → target.run → RunEndEvent → evaluate → feedback → close trajectory. Returns `(trajectory, evaluation, done)`.
- `_make_send_event(channel)` — creates the `EventHandler` callback that bridges target events to the channel with security domain filtering.

## Security domain filtering

The controller filters events based on the `security_domain_tag` parameter:

- For `ControllablePreCallEvent` and `ControllablePostCallEvent`: check `security_domain_tag.includes(event.controllable.spec.security_domain)`.
- **In scope**: Forward through channel to optimizer, return its response.
- **Out of scope**: Return `NoModification(event=event)` without consulting the optimizer.

Filtering happens in the `send_event` callback, before events reach the channel. This allows testing specific security boundaries — scoping to `external` tests only external-facing controllables, while scoping to `root` tests everything.

## Event log

`controller.event_log` returns all `(Event, EventResponse)` pairs from controllable events across all runs. Thread-safe (protected by `threading.Lock`).

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
- **Multi-run loop**: Runs until optimizer signals `RunEndResponse(done=True)` or `max_runs_per_task` safety limit.
- **Concurrent optimizer**: `optimizer.run(channel)` is launched as an `asyncio.Task`. The optimizer stays alive across all runs for a task — one channel, one optimizer task per task.
- **Cleanup after each run**: `target.cleanup()` is called after each evaluation to reset state.
- **Thread-safe event log**: Protected by `threading.Lock` for cross-thread safety.
- **CLI-ready**: Constructor takes plain parameters. A future CLI module can parse config, instantiate components, call `asyncio.run(controller.run())`. `ControllerResult` provides structured output for programmatic use.
