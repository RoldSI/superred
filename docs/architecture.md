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
0. User builds a TargetFactory wrapping the target constructor:
   target_factory = TargetFactory(
       create=lambda: MyTarget(api_key="sk-..."),
       concurrency=8,   # how many tasks may run in parallel
   )

1. Controller constructed with optimizer_factory, target_factory,
   security_claim, scope (required), llm_config (optional),
   max_runs_per_task (optional), results_dir (optional)

2. await controller.run():

   For each task in security_claim, bounded by target_factory.concurrency
   (asyncio.Semaphore + asyncio.gather; results in input order):
     a. target = target_factory.create()
        task.configure_target(target)
        → sets pre-run config via target.set_config()
        → raises NotApplicable if incompatible (task skipped)

     b. Create LLMClient from llm_config — fresh per task (budget is per-task)
        Create fresh optimizer via optimizer_factory()
        Filter controllables and observables by scope
        optimizer.initialize(goal, filtered_controllables, filtered_observables, llm_client)

     c. channel = EventChannel()
        optimizer_task = asyncio.create_task(optimizer.run(channel))

     d. For each run (until optimizer signals done or max_runs):
        Create Trajectory (full) and FilteredTrajectory (optimizer's view)
        channel.send(RunStartEvent(filtered_trajectory))
        target.run(emit, send_event)
          → target emits ObservableEvent instances via emit(event)
          → send_event bridges to channel with filtering
          → trajectory_recorder middleware records events/responses to trajectory
        task.evaluate(trajectory, target) → EvaluationResult
          → controller filters sub_scores by scope
        channel.send(RunEndEvent(evaluation=filtered_eval, security_domain=scope_tag))
          → RunEndEvent is persisted to the trajectory
          → optimizer responds with RunEndResponse(done=True/False)
        Close the trajectory
        target.cleanup() — resets target state for next run within this task
        If done=True, break
        On exception: preserve partial trajectory + zero-score evaluation;
                      capture exception traceback on TaskResult.error; break

     e. channel.close() → optimizer.run() exits
        await optimizer_task, optimizer.teardown()
        target.cleanup() (final) and target.teardown() — instance is discarded

   3. Per-task detail files were written incrementally as each task
      finished (when results_dir set).  Write the claim-level summary
      file now as the completion marker.
   4. Print summary to stdout
   5. Return ThreatModelResult

Sweeping multiple (scope, llm_config) combinations is the caller's job:
construct one Controller per combination and await asyncio.gather() them.
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

5. **Composable middleware**: `Middleware = Callable[[EventHandler], EventHandler]`. Wraps the event callback with zero overhead (function composition, no extra tasks or channels). `compose(a, b)(handler)` applies `a` outermost, `b` inner. Built-in: `security_domain_filter`, `trajectory_recorder`. Users can add logging, tracing, budget enforcement etc. as additional middleware.

6. **Manual values are constructor concerns**: API keys, credentials, etc. are passed to the target's constructor. Not part of the framework interface.

7. **Config and query are distinct target surfaces**: `ConfigSpec`/`set_config` for task-set pre-run state. `QuerySpec`/`query` for post-run evaluation queries. Different actors, different lifecycles.

8. **Tasks are stateless**: `configure_target` sets config, returns nothing. `evaluate` receives the target for on-demand queries. No internal target reference. Safe to re-iterate from SecurityClaims.

9. **Tasks are type-bound via generics**: `Task[MyRAGTarget]` gets type-safe access to the concrete target. `Task[Target]` discovers capabilities at runtime via `config_specs`/`query_specs`.

10. **Thread-safe at every boundary**: Trajectory (`threading.Lock`), EventChannel (`asyncio.Queue` + `call_soon_threadsafe`), EventEnvelope.respond (`Lock` + `call_soon_threadsafe`), LLMClient (`threading.Lock` on usage counters).

11. **Process-safe interface**: The EventChannel interface (send/receive/respond/close) is designed so a future process-safe implementation (multiprocessing, sockets) can be swapped in with the same contract.

12. **SecurityClaim composes**: From tasks (`from_tasks`) or from other claims (`from_claims`). Lazy chaining for claims-of-claims. Re-iterable since tasks are stateless.

13. **Runtime-defined types**: SecurityDomainTag is a frozen dataclass, not an enum. Target systems define their own instances at runtime.

14. **Values are always text**: ConfigSpec and QuerySpec use strings. The description documents the format contract. The target interprets the text.

15. **LLM access is part of the threat model**: The controller controls which model the optimizer can use and tracks budget (calls, USD cost). The `LLMConfig` (model, API base, API key, `max_cost`) is set at the experiment level. Budget enforcement is cost-based: `litellm.completion_cost()` computes USD per call from model pricing; pre-call checks raise `BudgetExhaustedError` when cumulative cost reaches `max_cost`. The optimizer receives a constrained `LLMClient` that locks the model and credentials — it cannot choose a different model. Budget is per-task (fresh `LLMClient` per task). Uses litellm internally for OpenAI-compatible chat completions.

## File Map

```
src/superred/core/
  channel.py           -- EventEnvelope, EventChannel (thread-safe)
  controller.py        -- Controller, TargetFactory, RunResult, TaskResult,
                          ThreatModelResult, OptimizerFactory
  llm.py               -- LLMClient (constrained LLM proxy for optimizers)
  middleware.py         -- Middleware type, compose(), security_domain_filter(),
                          trajectory_recorder()
  persistence.py       -- per-threat-model JSON serialization (used when the
                          Controller is given a results_dir; module-private)
  interfaces/
    optimizer.py       -- Optimizer ABC (actor model: run, on_event, _dispatch)
    target.py          -- Target ABC, EventHandler type alias
    task.py            -- Task[T_Target] ABC, NotApplicable exception
    security_claim.py  -- SecurityClaim (composable task iterator)
  types/
    goal.py            -- Goal
    llm.py             -- LLMConfig, LLMUsage, BudgetExhaustedError
    state.py           -- ConfigSpec, QuerySpec, QueryParam
    controllable.py    -- Controllable
    observable.py      -- Observable, ObservableValue
    event.py           -- Event, EventResponse base classes,
                          EventHandler / EventResponseHandler aliases
    events.py          -- ControllablePreCallEvent, ControllablePostCallEvent,
                          ControllableInjection, ControllableNoInjection,
                          ObservableEvent, RunStartEvent, RunEndEvent,
                          RunEndResponse
    trajectory.py      -- Trajectory, FilteredTrajectory, ReadableTrajectory,
                          TrajectoryItem, get_domain
    evaluation.py      -- Score, EvaluationResult
    security_domain.py -- SecurityDomainTag, SecurityDomain, Scope, scope_includes
```

## Detailed Component Documentation

- [Controller](controller.md) -- the orchestrator: event bridging, filtering, evaluation
- [Optimizer](optimizer.md) -- the optimizer interface: actor model, consumption choices
- [Target](target.md) -- target interface, config/query separation
- [Task](task.md) -- task generics, stateless design
- [SecurityClaim](security_claim.md) -- composable task collections
- [Types Reference](types.md) -- all core types, design decisions, relationships
