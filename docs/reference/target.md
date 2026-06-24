---
layout: doc
title: "Target Interface"
permalink: /reference/target
---

# Target Interface

The AI system under test. Exposes five surfaces and a lifecycle.

## Manual values (constructor)

API keys, credentials, and other user-provided secrets are passed directly to the target's constructor, not through the framework. This keeps the Target ABC clean and makes instantiation explicit:

```python
target = MyDockerTarget(api_key="sk-...", image="my-app:latest")
```

## Pre-run configuration (task-set)

- `config_specs -> list[ConfigSpec]`, declares named text-valued config slots with security domains.
- `set_config(name, value)`, accepts a config value before a run.

Used by tasks to set up initial state. The description on each ConfigSpec documents the accepted format, that is the contract between task and target.

## Post-run queries (evaluator uses)

- `query_specs -> list[QuerySpec]`, declares available post-run interactions (name, description, optional params).
- `query(name, **params) -> str`, executes a post-run query. May be a simple getter (no params) or a parameterized action.

Config and query are **intentionally distinct**:
- Config = task-set pre-run state, set per task.
- Query = post-run ground truth, may differ from what was configured.

## Security domain

- `security_domain -> SecurityDomain`, the security domain forest defined by this target. Classifies controllables and observables into a hierarchy of trust boundaries. Used by the controller to filter events by scope.

## Runtime surfaces

- `get_controllables() -> list[Controllable]`, injection points the optimizer can manipulate during a run. Each has a `security_domain` tag.
- `get_observables() -> list[ObservableValue]`, static context about the system (system prompts, source code, configs). Each has a `security_domain` tag.

## Execution

- `run(emit, send_event)`, execute one run. Emit events via `emit(event)` (an `EventHandler = Callable[[Event], None]`, typically `emit(ObservableEvent(observable=..., content=...))`). Call `await send_event(event)` at controllable points and use the response. The target no longer receives the full Trajectory object, only the emit function.
- `reset_ephemeral_state()`, reset ephemeral (per-run) state after each evaluation, before the next run (clear the active conversation or last response, reset containers, etc.). Durable state (e.g. an accumulated memory bank) must survive this call; it is discarded only when a fresh `TargetFactory` instance is obtained between tasks. Must be implemented even if a no-op.
- `teardown()`, release resources when all evaluation is done.

`EventResponseHandler = Callable[[Event], Awaitable[EventResponse]]`, the `send_event` callback type. The controller wraps it to bridge to the EventChannel with security domain filtering. The target doesn't know or care what's on the other end.

## Internal parallelism

The target can have concurrent branches, each calling `send_event` independently:

```python
async def run(self, emit, send_event):
    async def branch_a():
        resp = await send_event(event_a)  # suspends only this branch
        ...
    async def branch_b():
        resp = await send_event(event_b)  # suspends only this branch
        ...
    await asyncio.gather(branch_a(), branch_b())
```

Each `send_event` call creates its own future in the channel. Multiple events can be in-flight simultaneously. The optimizer processes them at its own pace.

For thread-based targets (Docker, subprocesses), bridge back to the event loop:

```python
async def run(self, emit, send_event):
    loop = asyncio.get_running_loop()
    def blocking_work():
        event = parse_event_from_subprocess(proc)
        future = asyncio.run_coroutine_threadsafe(send_event(event), loop)
        response = future.result()  # blocks thread until response
        ...
    await loop.run_in_executor(None, blocking_work)
```

## Design decisions

- **Manual values at construction**: Keeps the Target ABC clean. No `manual_specs`/`set_manual` in the interface. The target validates its own constructor arguments.
- **Config/query separation**: Different actors (task vs evaluator), different lifecycles (pre-run vs post-run), different security concerns.
- **Values are always text**: ConfigSpec and QuerySpec use strings. The description documents the format. The target interprets the text.
- **Parameterized queries**: `QuerySpec` has `params: list[QueryParam]`. Simple getters have no params. Actions (e.g. "search the DB for X") declare params with names and descriptions.
- **`send_event` as callback**: Decouples the target from the optimizer. The same target works with different controller implementations.
- **`reset_ephemeral_state` is required**: Even if a no-op, forces the implementor to think about inter-run state.
