# Architecture Overview

superred is a modular framework for red-teaming AI systems. It models the interaction between an **optimizer** (the attacker), a **target** (the AI system under test), and **tasks** (adversarial objectives), orchestrated through an event-driven, channel-based architecture.

## High-Level Flow

```
  SecurityClaim
    |  iterates tasks
    v
  Task[T_Target]
    |  configure_target(target)    (pre-run config)
    |  evaluate(trajectory, target) (post-run queries)
    v
  +---------------------------+
  |    Controller              |
  |  (security domain filter)  |
  +---------------------------+
    send_event ↕  EventChannel  ↕ channel
  +-------------+           +------------------+
  |   Target    |           |    Optimizer      |
  | (async run) |           | (actor, run loop) |
  +-------------+           +------------------+

Target.run(trajectory, send_event):
  - Emits trajectory entries
  - Calls send_event(Event) at controllable points
  - May have concurrent internal branches
  - Each branch awaits its own response independently
```

## Concurrency Model

```
Target (asyncio.Task / threads)     Controller          Optimizer (asyncio.Task)
  |                                    |                    |
  | branch_a: await send_event(e1) →   | filter → channel  →  |
  | branch_b: await send_event(e2) →   | filter → channel  →  |
  |                                    |                    |
  | (branches suspended)               |    run(): async for envelope in channel:
  |                                    |      on_event(e1) → respond(r1)
  |                                    |      on_event(e2) → respond(r2)
  |                                    |                    |
  | branch_a: ← r1 (resumes)          |                    |
  | branch_b: ← r2 (resumes)          |                    |
```

The target and optimizer run as independent concurrent tasks. Communication flows through an `EventChannel` — a thread-safe bidirectional event-response channel. The controller bridges the target's `send_event` callback to the channel, applying security domain filtering.

## Initialization and Run (Single Run per Task)

```
0. User provides manual values (API keys etc.)
   → target.set_manual(values)

1. task.configure_target(target)
   → sets pre-run config via target.set_config()

2. optimizer.initialize(goal, controllables, observables)

3. channel = EventChannel()
   optimizer_task = asyncio.create_task(optimizer.run(channel))

4. channel.send(RunStartEvent(trajectory))
   → optimizer receives, sets current trajectory

5. target.run(trajectory, send_event)
   → send_event bridges to channel with security domain filtering
   → target may have concurrent branches, each calling send_event

6. channel.send(RunEndEvent(trajectory))
   → optimizer responds with RunEndResponse(done=True/False)
   → optimizer archives trajectory

7. task.evaluate(trajectory, target)
   → append FeedbackResult to trajectory, close it

8. channel.close() → optimizer.run() exits
9. optimizer.teardown(), target.teardown()
```

## Key Design Decisions

1. **Channel-based communication**: `EventChannel` decouples target and optimizer. The target puts events via `send_event` callback (bridged to `channel.send`). The optimizer pulls from the channel at its own pace. Thread-safe: `respond()` and `close()` use `call_soon_threadsafe`.

2. **Optimizer consumption model is the optimizer's choice**: The default `run()` processes events sequentially. Override for parallel consumption (spawn tasks per envelope) or continuous execution (background work + event processing).

3. **Lifecycle events replace hooks**: `RunStartEvent`/`RunEndEvent` flow through the channel like any other event. No special method calls. The base Optimizer's `_dispatch()` wrapper handles trajectory tracking automatically.

4. **Target internal parallelism**: The target can spawn concurrent branches, each calling `send_event` independently. Each call gets its own response via the channel's future-based mechanism.

5. **Three distinct target surfaces**: `ManualSpec`/`set_manual` for user-provided secrets (via controller), `ConfigSpec`/`set_config` for task-set pre-run config, `QuerySpec`/`query` for post-run evaluation queries.

6. **Tasks are stateless**: `configure_target` returns what it set. `evaluate` receives the target for on-demand queries. No internal target reference.

7. **Tasks are type-bound via generics**: `Task[MyRAGTarget]` gets type-safe access to the concrete target. `Task[Target]` discovers capabilities at runtime.

8. **Thread-safe everything**: Trajectory (threading.Lock), EventChannel (asyncio.Queue + call_soon_threadsafe), EventEnvelope.respond (Lock + call_soon_threadsafe), Controller event log (threading.Lock).

9. **Process-safe interface**: The EventChannel interface (send/receive/respond/close) is designed so a future process-safe implementation can be swapped in with the same contract.

10. **SecurityClaim composes**: From tasks (`from_tasks`) or from other claims (`from_claims`). Lazy chaining for claims-of-claims.

## File Map

```
src/superred/core/
  controller.py        -- Controller, TaskResult, ControllerResult
  interfaces/
    optimizer.py       -- Optimizer ABC (actor model: run, on_event, _dispatch)
    target.py          -- Target ABC, EventHandler type alias
    task.py            -- Task[T_Target] ABC, NotApplicable exception
    security_claim.py  -- SecurityClaim (composable task iterator)
  types/
    channel.py         -- EventEnvelope, EventChannel (thread-safe)
    goal.py            -- Goal
    state.py           -- ManualSpec, ConfigSpec, QuerySpec, QueryParam
    controllable.py    -- ControllableSpec, Controllable, RequestAnswerPair
    observable.py      -- Observable, ObservableValue
    event.py           -- Event, EventResponse, Controllable*Event,
                          ControllableInjection, NoModification,
                          RunStartEvent, RunEndEvent, RunEndResponse
    trajectory.py      -- TrajectoryEntryType, TrajectoryEntry, Trajectory
    evaluation.py      -- Score, EvaluationResult, FeedbackResult
    security_domain.py -- SecurityDomainTag, SecurityDomain
```

## Detailed Component Documentation

- [Controller](controller.md) -- the orchestrator: event bridging, filtering, evaluation
- [Optimizer](optimizer.md) -- the optimizer interface: actor model, consumption choices
- [Target](target.md) -- target interface, manual/config/query separation
- [Task](task.md) -- task generics, stateless design
- [SecurityClaim](security_claim.md) -- composable task collections
- [Types Reference](types.md) -- all core types, design decisions, relationships
