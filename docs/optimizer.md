# Optimizer Interface

The optimizer is the attacker agent in superred. It runs as a concurrent actor, receiving events through an `EventChannel` and deciding what to inject at controllable points.

## Lifecycle

```
1. Instantiate with configuration
2. initialize(goal, controllables, observables, llm_client) — base class stores the LLM client
3. run(channel) — launched as asyncio.Task by the controller
   For each run (until optimizer signals done):
     - Receives RunStartEvent(trajectory) → sets current_trajectory
     - Receives ControllablePreCallEvent / ControllablePostCallEvent [0..N]
     - (controller evaluates)
     - Receives RunEndEvent(evaluation) → archives trajectory
       evaluation is on the event and RunEndEvent is persisted to the trajectory.
       Respond with RunEndResponse(done=True) to stop, done=False to continue
   Channel closes → run() returns
4. teardown()
```

The optimizer stays alive across all runs for a task. One channel, one `run()` task. Multiple RunStart/RunEnd cycles flow through the same channel.

## What to implement

Subclass `Optimizer` and override:

**Required:**
- `initialize(goal, controllables, observables, llm_client)` — setup before first run. Call `super().initialize(...)` to store the LLM client (accessible via `self.llm` after that).
- `on_event(event) -> EventResponse` — respond to a single event. Use `isinstance` dispatch.

**Optional:**
- `run(channel)` — override for custom consumption model. Default: sequential via `_dispatch`.
- `teardown()` — release resources. Default: no-op.

## LLM access

The controller passes a constrained `LLMClient` to `initialize()`. The base class stores it; after calling `super().initialize(...)`, the optimizer accesses it via:

- **`self.llm`** property — returns the `LLMClient`. Available after `super().initialize()` is called.

The `LLMClient` locks the model, API base, and API key — the optimizer cannot change them. Cost budget (`max_cost` in USD) is enforced by the client via pre-call checks that raise `BudgetExhaustedError`. Cost is computed per call via `litellm.completion_cost()`.

```python
async def on_event(self, event):
    if isinstance(event, ControllablePreCallEvent):
        response = await self.llm.complete([
            {"role": "system", "content": "You are a red-teaming assistant."},
            {"role": "user", "content": f"Generate an attack for: {event.request}"},
        ])
        attack = response.choices[0].message.content
        return ControllableInjection(event=event, controllable=event.controllable, value=attack)
    ...
```

## Consumption models

The optimizer chooses how to process events by overriding `run()`:

**Sequential (default)** — inherit `run()`, just override `on_event`:
```python
async def on_event(self, event):
    if isinstance(event, ControllablePreCallEvent):
        return ControllableInjection(event=event, controllable=event.controllable, value="...")
    elif isinstance(event, RunStartEvent):
        return EventResponse(event=event)
    elif isinstance(event, RunEndEvent):
        done = self._budget_exhausted()
        return RunEndResponse(event=event, done=done)
    return EventResponse(event=event)
```

**Parallel** — override `run()`, spawn tasks per event:
```python
async def run(self, channel):
    tasks = set()
    async for envelope in channel:
        task = asyncio.create_task(self._dispatch(envelope))
        tasks.add(task)
        task.add_done_callback(tasks.discard)
    if tasks:
        await asyncio.gather(*tasks)
```

**Continuous with events** — override `run()`, do background work + pull events:
```python
async def run(self, channel):
    self._done = False
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
2. Calls `on_event(event)` to get the response
3. Archives trajectory to `_past_trajectories` on `RunEndEvent`, clears `_current_trajectory`
4. Calls `envelope.respond(response)` to deliver the response back through the channel

**Exception safety**: If `on_event()` raises, `_dispatch` archives the trajectory only when the failing event is a `RunEndEvent`, rejects the envelope (propagating the exception to the sender), and re-raises.

Use `_dispatch` from custom `run()` implementations to retain automatic trajectory tracking. Advanced optimizers can handle envelopes directly if they want full control.

## Exception handling

The default `run()` iterates the channel via `async for envelope in channel: await self._dispatch(envelope)`.

If `on_event()` raises, `_dispatch` rejects the envelope (propagating the exception to the sender) and re-raises. The exception exits `run()` and the controller detects the failure. The controller then poisons the channel via `channel.set_error()`, ensuring no other `channel.send()` call deadlocks.

## Lifecycle events

Instead of hook methods, the optimizer receives lifecycle events through the channel:

- `RunStartEvent(trajectory)` — new run starting. The trajectory for this run is available via `self.current_trajectory` after `_dispatch` processes this event. Respond with `EventResponse(event=event)`.
- `RunEndEvent(evaluation)` — run completed. Sent after evaluation. The optimizer reads feedback directly from `event.evaluation`, or from past trajectories (since `RunEndEvent` is persisted to the trajectory). Respond with `RunEndResponse(event=event, done=False)` to continue with more runs, or `RunEndResponse(event=event, done=True)` to signal the optimizer is finished (goal achieved, budget exhausted).

These flow through the channel like any other event. No special methods to override.

## History tracking

- `current_trajectory -> ReadableTrajectory | None` — trajectory for the currently active run. When provided by the controller, this is a `FilteredTrajectory` that only exposes entries within the security domain scope. Set by `_dispatch` on `RunStartEvent`, cleared on `RunEndEvent`. `None` between runs.
- `past_trajectories -> list[ReadableTrajectory]` — all completed run trajectories, oldest first. Archived by `_dispatch` on `RunEndEvent`.

Both managed automatically by `_dispatch()`. If you override `run()` and don't use `_dispatch`, you manage trajectory state yourself.

## Thread safety

- `on_event` may be called concurrently if `run()` is overridden for parallel consumption. The implementation must handle its own synchronization (e.g. `asyncio.Lock`).
- `envelope.respond()` is thread-safe — can be called from any thread via `call_soon_threadsafe`.
- `EventChannel` is thread-safe — supports cross-thread communication.

## Design decisions

- **Actor model**: The optimizer runs as its own concurrent `asyncio.Task`. It is not called synchronously by the controller.
- **Channel-based**: Events flow through `EventChannel`, not direct method calls. This decouples the optimizer from the target's execution.
- **Optimizer chooses consumption**: Sequential, parallel, or continuous — the optimizer controls how it processes events by overriding `run()`.
- **Lifecycle events over hooks**: `RunStartEvent`/`RunEndEvent` flow through the same channel as controllable events. Uniform interface — no special methods to override.
- **`_dispatch` for convenience**: Handles trajectory bookkeeping and envelope response. Optional — advanced optimizers can handle envelopes directly.
- **Base class tracks trajectories**: `_current_trajectory` and `_past_trajectories` are managed by the base class via `_dispatch`. This is the common case — most optimizers want trajectory history without boilerplate.
- **Exception-safe by default**: `_dispatch` rejects the envelope on `on_event` failure (propagating the exception to the sender) and re-raises, exiting `run()` on the first error. The controller poisons the channel via `set_error()` to prevent deadlock.
