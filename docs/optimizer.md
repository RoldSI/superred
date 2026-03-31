# Optimizer Interface

The optimizer is the central agent in superred. It responds to events from the target system and decides what to inject at controllable points.

## Lifecycle

```
1. Instantiate
2. initialize(goal, controllables, observables)
3. For each run:
   a. _on_run_start(trajectory)
      -> sets current_trajectory
      -> calls pre_run()
   b. _handle_event(event) -> EventResponse   [0..N times]
   c. _on_run_end()
      -> calls post_run() (may return OptimizerDoneEvent)
      -> archives trajectory to past_trajectories
4. teardown()
```

## What to implement

Subclass `Optimizer` and override:

**Required:**
- `initialize(goal, controllables, observables)` — setup before first run.
- `on_event(event) -> EventResponse` — respond to events. Use `isinstance` dispatch.

**Optional:**
- `pre_run()` — called after trajectory is set, before target starts. Trajectory is accessible via `self.current_trajectory`.
- `post_run() -> OptimizerDoneEvent | None` — called after run ends, before trajectory is archived. Return `OptimizerDoneEvent` to stop the loop. Trajectory still accessible.

## Internal methods (framework only, do not override)

- `_on_run_start(trajectory)` — sets trajectory, then calls `pre_run()`.
- `_on_run_end()` — calls `post_run()`, then archives trajectory. Returns the done event if any.
- `_handle_event(event)` — delegates to `on_event()`.

Prefixed with `_` to signal they are not part of the public optimizer API.

## History tracking

- `current_trajectory` — trajectory for the active run (None between runs).
- `past_trajectories` — all completed trajectories, oldest first.

## Design decisions

- **Hooks wrap internal methods**: `_on_run_start`/`_on_run_end` do bookkeeping and call the overridable `pre_run`/`post_run`. This ensures trajectory is set before `pre_run` and archived after `post_run`.
- **`post_run` returns done signal**: The optimizer decides when it's finished. The framework checks the return value and stops scheduling runs.
- **No trajectory param on `on_event`**: Access via `self.current_trajectory`.
- **Async `on_event`**: Supports optimizers that call LLM APIs or do I/O.
- **`_on_run_end` asserts**: Double call without intervening start is a framework bug.
