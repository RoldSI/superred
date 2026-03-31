# Architecture Overview

superred is a modular framework for red-teaming AI systems. It models the interaction between an **optimizer** (the attacker), a **target** (the AI system under test), and **tasks** (adversarial objectives), orchestrated through an event-driven loop.

## High-Level Flow

```
  SecurityClaim
    |  iterates tasks
    v
  Task[T_Target]
    |  configure(target) -> dict[str, str]   (pre-run config)
    |  evaluate(trajectory, target)          (post-run ground truth)
    v
  +---------------------------+
  | Superred Controller (TBD)  |
  +---------------------------+
           |          ^
  events   |          |  responses
           v          |
  +---------------------------+
  |        Optimizer           |
  | (maintains run history)    |
  +---------------------------+

Target.run(trajectory, send_event):
  - Emits trajectory entries
  - Calls send_event(Event) at controllable points
  - Receives EventResponse (injection) and continues
```

## Initialization and Run Loop

```
1. Task.configure(target)
   -> sets pre-run config via target.set_config()
   -> returns cached config dict

2. Optimizer.initialize(goal, controllables, observables)

3. For each run:
   a. Optimizer._on_run_start(trajectory)
      -> sets trajectory, calls pre_run()
   b. Target.run(trajectory, send_event)
      -> at each controllable: send_event(Event) -> EventResponse
   c. Optimizer._on_run_end()
      -> calls post_run() (may return OptimizerDoneEvent)
      -> archives trajectory

4. Task.evaluate(trajectory, target)
   -> queries post-run state via target.get_state()

5. Optimizer.teardown()
```

## Key Design Decisions

1. **Config vs state are distinct**: `ConfigSpec`/`set_config` is pre-run setup (what the task configures). `StateSpec`/`get_state` is post-run ground truth (what the evaluator queries). These are intentionally separate on the Target.

2. **Tasks are stateless**: `configure` returns what it set (framework caches this). `evaluate` receives the target for on-demand queries. No internal target reference.

3. **Tasks are type-bound via generics**: `Task[MyRAGTarget]` gets type-safe access to the concrete target. `Task[Target]` discovers capabilities at runtime via `config_specs`/`state_specs`.

4. **Synchronous event-response**: The target pauses at each controllable, sends an event via `send_event` callback, and blocks until the optimizer returns a response.

5. **State is always text**: ConfigSpec and StateSpec values are strings. The description documents the format contract. The target interprets the text (run SQL, parse JSON, etc.).

6. **Runtime-defined types**: SecurityDomainTag and TrajectoryEntryType are frozen dataclasses, not enums. Target systems define their own instances at runtime.

7. **Thread-safe trajectory**: Trajectory uses a threading.Lock for all public methods.

8. **Non-blocking consumption only**: Use `drain()` (new since last call) or `snapshot()` (entire history).

9. **EventResponse references Event**: Enables the planned controller to correlate events and responses across queues.

10. **SecurityClaim composes**: From tasks (`from_tasks`) or from other claims (`from_claims`). Lazy chaining for claims-of-claims. Re-iterable since tasks are stateless.

## Planned: Controller

A controller will sit between target and optimizer with two queues (target-->controller, controller-->optimizer). The controller records all events and responses for observability and replay. The `EventHandler` callback abstraction already supports this — the target doesn't know whether it's talking to the optimizer directly or through a controller.

## File Map

```
src/superred/core/
  interfaces/
    optimizer.py       -- Optimizer ABC
    target.py          -- Target ABC, EventHandler type alias
    task.py            -- Task[T_Target] ABC, NotApplicable exception
    security_claim.py  -- SecurityClaim (composable task iterator)
  types/
    goal.py            -- Goal
    state.py           -- ConfigSpec (pre-run), StateSpec (post-run)
    controllable.py    -- ControllableSpec, Controllable, RequestAnswerPair
    observable.py      -- Observable, ObservableValue
    event.py           -- Event, EventResponse, Controllable*Event,
                          ControllableInjection, OptimizerDoneEvent
    trajectory.py      -- TrajectoryEntryType, TrajectoryEntry, Trajectory
    feedback.py        -- Score, EvaluationResult, FeedbackResult
    security.py        -- SecurityDomainTag, SecurityDomain
```

## Detailed Component Documentation

- [Optimizer](optimizer.md) -- the optimizer interface and lifecycle
- [Target](target.md) -- target interface, config/state separation
- [Task](task.md) -- task generics, stateless design
- [SecurityClaim](security_claim.md) -- composable task collections
- [Types Reference](types.md) -- all core types, design decisions, relationships
