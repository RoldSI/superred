# Architecture Overview

superred is a modular framework for red-teaming AI systems. It models the interaction between an **optimizer** (the attacker), a **target** (the AI system under test), and **tasks** (adversarial objectives), orchestrated through an event-driven loop.

## High-Level Flow

```
  SecurityClaim
    |  iterates tasks
    v
  Task[T_Target]
    |  configure(target) -> dict[str, str]   (pre-run config)
    |  evaluate(trajectory, target)          (post-run queries)
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
0. User provides manual values (API keys etc.)
   -> target.set_manual(values)

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
   -> queries post-run ground truth via target.query(name, **params)

5. Optimizer.teardown()
6. Target.teardown()
```

## Key Design Decisions

1. **Three distinct target surfaces**: `ManualSpec`/`set_manual` for user-provided secrets (via controller), `ConfigSpec`/`set_config` for task-set pre-run config, `QuerySpec`/`query` for post-run evaluation queries. These are intentionally separate.

2. **Post-run queries are parameterized**: `QuerySpec` can declare `params: list[QueryParam]`. The evaluator calls `target.query(name, **params)`. This supports both simple getters and actions.

3. **Tasks are stateless**: `configure` returns what it set (framework caches this). `evaluate` receives the target for on-demand queries. No internal target reference.

4. **Tasks are type-bound via generics**: `Task[MyRAGTarget]` gets type-safe access to the concrete target. `Task[Target]` discovers capabilities at runtime via `config_specs`/`query_specs`.

5. **Synchronous event-response**: The target pauses at each controllable, sends an event via `send_event` callback, and blocks until the optimizer returns a response.

6. **Values are always text**: ConfigSpec, ManualSpec, QuerySpec — all text. The description documents the format contract. The target interprets the text.

7. **Runtime-defined types**: SecurityDomainTag and TrajectoryEntryType are frozen dataclasses, not enums. Target systems define their own instances at runtime.

8. **Thread-safe trajectory**: Trajectory uses a threading.Lock for all public methods.

9. **Non-blocking consumption only**: Use `drain()` (new since last call) or `snapshot()` (entire history).

10. **EventResponse references Event**: Enables the planned controller to correlate events and responses across queues.

11. **SecurityClaim composes**: From tasks (`from_tasks`) or from other claims (`from_claims`). Lazy chaining for claims-of-claims. Re-iterable since tasks are stateless.

## Planned: Controller

A controller will sit between target and optimizer with two queues (target-->controller, controller-->optimizer). The controller records all events and responses for observability and replay. The `EventHandler` callback abstraction already supports this — the target doesn't know whether it's talking to the optimizer directly or through a controller. The controller also handles collecting manual values from the user.

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
    state.py           -- ManualSpec, ConfigSpec, QuerySpec, QueryParam
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
- [Target](target.md) -- target interface, manual/config/query separation
- [Task](task.md) -- task generics, stateless design
- [SecurityClaim](security_claim.md) -- composable task collections
- [Types Reference](types.md) -- all core types, design decisions, relationships
