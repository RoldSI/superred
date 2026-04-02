# Architecture Overview

superred is a modular framework for red-teaming AI systems. It models the interaction between an **optimizer** (the attacker), a **target** (the AI system under test), and **tasks** (adversarial objectives), orchestrated by a **controller** through an event-driven, channel-based architecture.

## High-Level Flow

```
  SecurityClaim
    |  iterates tasks
    v
  Task[T_Target]
    |  configure_target(target)     (pre-run config)
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
```

## Concurrency Model

The controller bridges the target and optimizer through an `EventChannel`. The target and optimizer run as independent concurrent asyncio tasks on a single event loop. Communication is cooperative — coroutines yield at `await` points, and the event loop scheduler interleaves them.

```
Target (asyncio.Task / threads)     Controller          Optimizer (asyncio.Task)
  |                                    |                    |
  | branch_a: await send_event(e1) →   | filter → channel  →  |
  | branch_b: await send_event(e2) →   | filter → channel  →  |
  |                                    |                    |
  | (branches suspended on futures)    |    run(): async for envelope in channel:
  |                                    |      on_event(e1) → respond(r1)
  |                                    |      on_event(e2) → respond(r2)
  |                                    |                    |
  | branch_a: ← r1 (resumes)          |                    |
  | branch_b: ← r2 (resumes)          |                    |
```

**Target internal parallelism**: The target can spawn concurrent branches (via `asyncio.gather` or `asyncio.create_task`), each calling `send_event` independently. Each call creates its own future and suspends only that branch. Other branches continue independently. For thread-based targets (Docker, subprocesses), use `asyncio.run_coroutine_threadsafe` to bridge back to the event loop.

**Optimizer consumption choice**: The default `run()` processes events sequentially. Override for parallel (spawn tasks per envelope), continuous (background work + event processing), or any custom model. The optimizer controls its own concurrency.

## Initialization and Run Loop

```
0. User instantiates target with manual values (API keys, etc.)
   → target = MyTarget(api_key="sk-...")

1. Controller constructed with optimizer, target, security_claim,
   security_domain_tag, max_runs_per_task

2. await controller.run():

   For each task in security_claim:
     a. task.configure_target(target)
        → sets pre-run config via target.set_config()
        → raises NotApplicable if incompatible (task skipped)

     b. optimizer.initialize(goal, controllables, observables)

     c. channel = EventChannel()
        optimizer_task = asyncio.create_task(optimizer.run(channel))

     d. For each run (until optimizer signals done or max_runs):
        i.   channel.send(RunStartEvent(trajectory))
        ii.  target.run(trajectory, send_event)
             → send_event bridges to channel with security domain filtering
        iii. channel.send(RunEndEvent(trajectory))
             → optimizer responds with RunEndResponse(done=True/False)
        iv.  task.evaluate(trajectory, target)
             → appends FeedbackResult to trajectory, closes it
        v.   target.cleanup()
             → resets target state for next run
        vi.  If done=True, break

     e. channel.close() → optimizer.run() exits
        await optimizer_task

   3. Print summary to stdout
   4. optimizer.teardown(), target.teardown()
   5. Return ControllerResult
```

## asyncio Runtime

There is one event loop on one thread. The caller provides it:

```python
result = asyncio.run(controller.run())
```

The controller does not create its own event loop. This allows embedding in larger async applications (web servers, notebooks, pipelines). Tests use pytest-asyncio which provides the loop.

## Key Design Decisions

1. **Channel-based communication**: `EventChannel` decouples target and optimizer. The target puts events via `send_event` callback (bridged to `channel.send`). The optimizer pulls from the channel at its own pace. Thread-safe: `respond()` and `close()` use `call_soon_threadsafe`.

2. **Optimizer as actor**: The optimizer runs as its own `asyncio.Task`, not called synchronously. It chooses its consumption model (sequential, parallel, continuous).

3. **Lifecycle events replace hooks**: `RunStartEvent`/`RunEndEvent` flow through the channel like any other event. No special method calls. The base Optimizer's `_dispatch()` wrapper handles trajectory tracking automatically.

4. **Target internal parallelism**: Multiple concurrent branches each calling `send_event` independently. Each gets its own response via the channel's future-based mechanism. Supports asyncio tasks and thread bridging.

5. **Manual values are constructor concerns**: API keys, credentials, etc. are passed to the target's constructor. Not part of the framework interface.

6. **Config and query are distinct target surfaces**: `ConfigSpec`/`set_config` for task-set pre-run state. `QuerySpec`/`query` for post-run evaluation queries. Different actors, different lifecycles.

7. **Tasks are stateless**: `configure_target` sets config, returns nothing. `evaluate` receives the target for on-demand queries. No internal target reference. Safe to re-iterate from SecurityClaims.

8. **Tasks are type-bound via generics**: `Task[MyRAGTarget]` gets type-safe access to the concrete target. `Task[Target]` discovers capabilities at runtime via `config_specs`/`query_specs`.

9. **Thread-safe at every boundary**: Trajectory (`threading.Lock`), EventChannel (`asyncio.Queue` + `call_soon_threadsafe`), EventEnvelope.respond (`Lock` + `call_soon_threadsafe`), Controller event log (`threading.Lock`).

10. **Process-safe interface**: The EventChannel interface (send/receive/respond/close) is designed so a future process-safe implementation (multiprocessing, sockets) can be swapped in with the same contract.

11. **SecurityClaim composes**: From tasks (`from_tasks`) or from other claims (`from_claims`). Lazy chaining for claims-of-claims. Re-iterable since tasks are stateless.

12. **Runtime-defined types**: SecurityDomainTag and TrajectoryEntryType are frozen dataclasses, not enums. Target systems define their own instances at runtime.

13. **Values are always text**: ConfigSpec and QuerySpec use strings. The description documents the format contract. The target interprets the text.

## File Map

```
src/superred/core/
  controller.py        -- Controller, RunResult, TaskResult, ControllerResult
  interfaces/
    optimizer.py       -- Optimizer ABC (actor model: run, on_event, _dispatch)
    target.py          -- Target ABC, EventHandler type alias
    task.py            -- Task[T_Target] ABC, NotApplicable exception
    security_claim.py  -- SecurityClaim (composable task iterator)
  types/
    channel.py         -- EventEnvelope, EventChannel (thread-safe)
    goal.py            -- Goal
    state.py           -- ConfigSpec, QuerySpec, QueryParam
    controllable.py    -- ControllableSpec, Controllable, RequestAnswerPair
    observable.py      -- Observable, ObservableValue
    event.py           -- Event, EventResponse, ControllablePreCallEvent,
                          ControllablePostCallEvent, ControllableInjection,
                          NoModification, RunStartEvent, RunEndEvent,
                          RunEndResponse
    trajectory.py      -- TrajectoryEntryType, TrajectoryEntry, Trajectory
    evaluation.py      -- Score, EvaluationResult, FeedbackResult
    security_domain.py -- SecurityDomainTag, SecurityDomain
```

## Detailed Component Documentation

- [Controller](controller.md) -- the orchestrator: event bridging, filtering, evaluation
- [Optimizer](optimizer.md) -- the optimizer interface: actor model, consumption choices
- [Target](target.md) -- target interface, config/query separation
- [Task](task.md) -- task generics, stateless design
- [SecurityClaim](security_claim.md) -- composable task collections
- [Types Reference](types.md) -- all core types, design decisions, relationships
