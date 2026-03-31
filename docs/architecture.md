# Architecture Overview

superred is a modular framework for red-teaming AI systems. It models the interaction between an **optimizer** (the attacker) and a **target AI system** through an event-driven optimization loop.

## High-Level Flow

```
                  +---------------------------+
                  | Superred Controller (TBD)  |
                  +---------------------------+
                           |          ^
               events      |          |  responses
                           v          |
                  +---------------------------+
                  |        Optimizer           |
                  | (maintains run history)    |
                  +---------------------------+

Initialization:
  Goal + ObservableValues + Controllables --> optimizer.initialize()

Per iteration (= one run of the target system):
  _on_run_start(trajectory)
    -> sets trajectory, calls on_pre_run()
    -> target runs, pauses at each controllable:
         ControllablePreCallEvent  --> on_event() --> ControllableInjection
         ControllablePostCallEvent --> on_event() --> ControllableInjection
    -> target finishes
  _on_run_end()
    -> calls on_post_run() (may return OptimizerDoneEvent to stop)
    -> archives trajectory to history

teardown()
```

## Key Design Decisions

1. **Synchronous event-response**: The target pauses at each controllable, sends an event, and blocks until the optimizer returns a response. This is call-and-return, not fire-and-forget.

2. **Runtime-defined types**: SecurityDomainTag and TrajectoryEntryType are frozen dataclasses, not enums. Target systems define their own instances at runtime.

3. **Thread-safe trajectory**: Trajectory uses a threading.Lock for all public methods. Multiple threads can emit, drain, and snapshot concurrently.

4. **Non-blocking consumption only**: Trajectory does not support blocking `async for`. Use `drain()` (new since last call) or `snapshot()` (entire history).

5. **EventResponse references Event**: Every response carries a reference to the event that triggered it. This enables the planned controller to correlate events and responses flowing through separate queues.

## Planned: Controller

A controller will sit between target and optimizer with two queues (target-->controller, controller-->optimizer). The controller records all events and responses for observability and replay. Each queue will be a separate Trajectory. Not yet implemented but the current design is compatible.

## File Map

```
src/superred/core/
  interfaces/
    optimizer.py     -- Optimizer ABC
  types/
    goal.py          -- Goal
    controllable.py  -- ControllableSpec, Controllable, RequestAnswerPair
    observable.py    -- Observable, ObservableValue
    event.py         -- Event, EventResponse, Controllable*Event,
                        ControllableInjection, OptimizerDoneEvent
    trajectory.py    -- TrajectoryEntryType, TrajectoryEntry, Trajectory
    feedback.py      -- Score, EvaluationResult, FeedbackResult
    security.py      -- SecurityDomainTag, SecurityDomain
```

## Detailed Component Documentation

- [Optimizer](optimizer.md) -- the optimizer interface and lifecycle
- [Types Reference](types.md) -- all core types, design decisions, relationships
