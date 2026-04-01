# Controller

The controller is the main orchestrator for red-teaming evaluations. It wires together an optimizer, target, and security claim, managing the full lifecycle with channel-based communication.

## Construction

```python
controller = Controller(
    optimizer=my_optimizer,
    target=my_target,
    security_claim=claim,
    security_domain_tag=external_tag,
    manual_values={"api_key": "sk-..."},
)
```

Constructor validates that all required `ManualSpec` values are provided. Raises `ValueError` if any are missing.

## Run lifecycle

`await controller.run() -> ControllerResult`:

1. **Manual setup**: `target.set_manual(manual_values)`.
2. **Per task** (from security claim):
   - `task.configure_target(target)` — if `NotApplicable`, skip task.
   - `optimizer.initialize(goal, controllables, observables)`.
   - Create `EventChannel`, launch `optimizer.run(channel)` as concurrent task.
   - Send `RunStartEvent` through channel.
   - `target.run(trajectory, send_event)` — `send_event` bridges to channel with security domain filtering.
   - Send `RunEndEvent` through channel — check `RunEndResponse.done`.
   - `task.evaluate(trajectory, target)` — append `FeedbackResult` to trajectory, close it.
   - Close channel, await optimizer task.
   - Collect `TaskResult`.
3. **Summary**: Print human-readable results to stdout.
4. **Teardown**: `optimizer.teardown()`, `target.teardown()`.
5. **Return** `ControllerResult`.

## Security domain filtering

The controller filters events based on the `security_domain_tag` parameter:

- For `ControllablePreCallEvent` and `ControllablePostCallEvent`: check `security_domain_tag.includes(event.controllable.spec.security_domain)`.
- **In scope**: Forward through channel to optimizer, return its response.
- **Out of scope**: Return `NoModification(event=event)` without consulting the optimizer.

Filtering happens in the `send_event` callback, before events reach the channel.

## Event log

`controller.event_log` returns all `(Event, EventResponse)` pairs from controllable events across all runs. Thread-safe (protected by `threading.Lock`).

## Result types

### TaskResult (frozen)

- `task`: The task that was evaluated.
- `evaluation`: The `EvaluationResult`.
- `trajectory`: The run `Trajectory`.
- `score`: The primary `Score`.
- `success`: Whether the adversarial goal was achieved.

### ControllerResult (frozen)

- `task_results`: List of `TaskResult` for each evaluated task.
- `skipped_tasks`: Tasks that raised `NotApplicable`.

## Design decisions

- **Concrete class, not ABC**: There is one orchestration logic.
- **Channel-based**: Controller creates an `EventChannel` per task. Target's `send_event` callback bridges to `channel.send()` with filtering. Optimizer pulls from channel in `run()`.
- **Single run per task**: Currently one `target.run()` per task. Multi-run loop will be added later.
- **Concurrent optimizer**: `optimizer.run(channel)` is launched as an `asyncio.Task`. Target and optimizer run concurrently.
- **Thread-safe event log**: Protected by `threading.Lock` for cross-thread safety.
- **CLI-ready**: Constructor takes plain parameters. A future CLI module can parse config → instantiate → call `run()`. `ControllerResult` provides structured output.
