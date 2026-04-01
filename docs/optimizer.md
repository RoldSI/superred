# Optimizer Interface

The optimizer is the attacker agent in superred. It runs as a concurrent actor, receiving events through an `EventChannel` and deciding what to inject at controllable points.

## Lifecycle

```
1. Instantiate
2. initialize(goal, controllables, observables)
3. run(channel) — launched as asyncio.Task
   - Receives RunStartEvent (sets current_trajectory)
   - Receives ControllablePreCallEvent / ControllablePostCallEvent [0..N]
   - Receives RunEndEvent (archives trajectory)
   - Channel closes → run() returns
4. teardown()
```

## What to implement

Subclass `Optimizer` and override:

**Required:**
- `initialize(goal, controllables, observables)` — setup before first run.
- `on_event(event) -> EventResponse` — respond to events. Use `isinstance` dispatch.

**Optional:**
- `run(channel)` — override for custom consumption model. Default: sequential via `_dispatch`.

## Consumption models

The optimizer chooses how to process events by overriding `run()`:

**Sequential (default)** — inherit `run()`, just override `on_event`:
```python
async def on_event(self, event):
    if isinstance(event, ControllablePreCallEvent):
        return ControllableInjection(event=event, value="...")
    elif isinstance(event, RunStartEvent):
        return EventResponse(event=event)
    elif isinstance(event, RunEndEvent):
        return RunEndResponse(event=event, done=False)
```

**Parallel** — override `run()`, spawn tasks per event:
```python
async def run(self, channel):
    tasks = set()
    async for envelope in channel:
        task = asyncio.create_task(self._dispatch(envelope))
        tasks.add(task)
        task.add_done_callback(tasks.discard)
    await asyncio.gather(*tasks)
```

**Continuous with events** — override `run()`, do background work + pull events:
```python
async def run(self, channel):
    async def event_loop():
        async for envelope in channel:
            await self._dispatch(envelope)
    async def background():
        while not self._done:
            await self._evolve_population()
    await asyncio.gather(event_loop(), background())
```

## `_dispatch(envelope)` — trajectory tracking wrapper

The base class provides `_dispatch()` which:
1. Sets `_current_trajectory` on `RunStartEvent`
2. Calls `on_event(event)` for the actual response
3. Archives trajectory to `_past_trajectories` on `RunEndEvent`
4. Calls `envelope.respond(response)`

Use `_dispatch` from custom `run()` implementations to retain automatic trajectory tracking.

## Lifecycle events

Instead of hook methods, the optimizer receives lifecycle events through the channel:

- `RunStartEvent(trajectory)` — new run starting. Respond with `EventResponse(event=event)`.
- `RunEndEvent(trajectory)` — run completed. Respond with `RunEndResponse(event=event, done=True/False)`. Set `done=True` to signal the optimizer wants to stop.

## History tracking

- `current_trajectory` — trajectory for the active run (None between runs).
- `past_trajectories` — all completed trajectories, oldest first.

Both managed automatically by `_dispatch()`.

## Thread safety

- `on_event` may be called concurrently if `run()` is overridden for parallel consumption. The implementation must handle its own synchronization.
- `envelope.respond()` is thread-safe — can be called from any thread.
- `EventChannel` is thread-safe — supports cross-thread communication.

## Design decisions

- **Actor model**: The optimizer runs as its own concurrent task. It is not called synchronously by the controller.
- **Channel-based**: Events flow through `EventChannel`, not direct method calls. This decouples the optimizer from the target's execution.
- **Optimizer chooses consumption**: Sequential, parallel, or continuous — the optimizer controls how it processes events.
- **Lifecycle events over hooks**: `RunStartEvent`/`RunEndEvent` flow through the same channel as controllable events. No special methods to override.
- **`_dispatch` for convenience**: Handles trajectory bookkeeping and envelope response. Optional — advanced optimizers can handle envelopes directly.
