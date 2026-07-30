---
layout: doc
title: "Optimizer"
permalink: /reference/optimizer
---

# Optimizer

The **optimizer** is the attacker. It is the only actively adversarial component:
it drives the target toward violating a security property, using only the access
the current threat model grants it. It acts **only** through
[controllables](/reference/types#controllable-controllablepy) and observes **only**
through [observables](/reference/types#observable-observablepy) and the
[trajectory](/reference/events-and-trajectory#trajectory); it never touches the
target directly.

An optimizer is an **actor**: the Controller launches its `run(channel)` as a
concurrent `asyncio.Task`, and the optimizer pulls
[events](/reference/events-and-trajectory#events-and-responses) off the channel at
its own pace and answers each one. You implement one by subclassing `Optimizer`.

## Lifecycle

```
1. Instantiate (no required construction arguments; see below).
2. initialize(goal, controllables, observables, llm_client)
      - the base class stores the LLM client (self.llm).
3. run(channel) - launched as an asyncio.Task by the Controller.
      Per run (until the optimizer signals done):
        RunStartEvent            → current_trajectory is set
        Controllable events ×N   → inject or decline
        RunEndEvent(evaluation)  → read feedback; answer RunEndResponse(done=…)
      The channel closes → run() returns.
4. teardown() - release resources.
```

The optimizer stays alive across **all** runs of a task: one channel, one `run()`
task, many run cycles.

**No construction configuration.** An `OptimizerFactory` is a plain
`Callable[[], Optimizer]` and the Controller builds fresh instances with no
arguments, so an optimizer must infer everything it needs at `initialize()` from
the goal, the controllables and observables it is handed, and (optionally) an LLM
call. This is what lets one optimizer attack any target under any scope.

## What to implement

Subclass `Optimizer` and override:

**Required**

- `async initialize(goal, controllables, observables, llm_client)` setup before
  the first run. Call `await super().initialize(...)` so the base class stores the
  client and `self.llm` works. The `controllables` are exactly the surfaces this
  threat model lets you inject into (already scope-filtered); a read-only surface
  is not here, it appears among `observables` instead.
- `async on_event(event) -> EventResponse` handle one event. Dispatch on type
  with `isinstance`.

**Optional**

- `async run(channel)` override for a non-sequential
  [consumption model](#consumption-models). Default: sequential via `_dispatch`.
- `async teardown()` release resources. Default: no-op.

## Responding to events

`on_event` returns one response per event. Each event class declares its valid
responses (its `response_types`), and the channel **validates** your reply against
them, so returning the wrong response type raises `TypeError` rather than passing
silently. The contract:

| Event | Return |
|-------|--------|
| `RunStartEvent` | any `EventResponse` (typically `EventResponse(event=event)`) |
| `ControllablePreCallEvent` | `ControllableInjection(event=event, controllable=event.controllable, value=...)` to act, or `ControllableNoInjection(event=event, controllable=event.controllable)` to decline |
| `ControllablePostCallEvent` | same two options (a chance to observe the effect and, if wanted, inject again) |
| `RunEndEvent` | `RunEndResponse(event=event, done=...)`, `done=True` to stop, `False` to try another run |

```python
async def on_event(self, event):
    if isinstance(event, ControllablePreCallEvent):
        return ControllableInjection(
            event=event, controllable=event.controllable, value="…attack…",
        )
    elif isinstance(event, RunStartEvent):
        return EventResponse(event=event)
    elif isinstance(event, RunEndEvent):
        done = self._satisfied(event.evaluation)   # decide from feedback
        return RunEndResponse(event=event, done=done)
    return EventResponse(event=event)
```

The optimizer is never asked about surfaces outside its scope: the Controller
answers those with `ControllableNoInjection` itself. Success is decided by the
[Task](/reference/task), not the optimizer; `event.evaluation` is for **steering**
the next attempt, not for self-certifying a win. An optimizer that always declines
is the passthrough baseline: it changes nothing and reproduces the target's
unattacked behavior.

## LLM access

The Controller passes a constrained [`LLMClient`](/reference/types#llmclient-corellmpy)
to `initialize()`; the base class stores it, and after `super().initialize(...)`
you reach it as **`self.llm`**. The client locks the model and credentials and
enforces the per-task cost cap: a call raises `BudgetExhaustedError` once the cap
is reached.

```python
response = await self.llm.complete([
    {"role": "system", "content": "You are a red-teaming assistant."},
    {"role": "user", "content": f"Craft an attack for: {event.request}"},
])
attack = response.choices[0].message.content
```

The model and the budget are fixed by the experiment, not the optimizer. An
optimizer designed for a fixed number of iterations should keep going until it
hits `BudgetExhaustedError`, rather than imposing its own iteration cap.

## Consumption models

The default `run()` consumes events one at a time. Override `run()` to change how,
but keep calling `self._dispatch(envelope)` so trajectory bookkeeping (below) still
happens.

**Sequential (default)** inherit `run()`, override only `on_event`:

```python
async def run(self, channel):
    async for envelope in channel:
        await self._dispatch(envelope)
```

**Parallel** spawn a task per envelope:

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

**Continuous** run background work alongside event handling (for example an
evolutionary optimizer evolving a population between injections):

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

If `run()` may call `on_event` concurrently, `on_event` must handle its own
synchronization (for example an `asyncio.Lock`).

## `_dispatch(envelope)`: trajectory bookkeeping

The base class provides `_dispatch`, which wraps `on_event`:

1. On a `RunStartEvent`, set `_current_trajectory` from the event.
2. Call `on_event(event)` to get the response.
3. On a `RunEndEvent`, archive the current trajectory into `_past_trajectories`
   and clear `_current_trajectory`.
4. Deliver the response with `envelope.respond(response)`.

**Exception safety.** If `on_event` raises, `_dispatch` still runs the post-event
lifecycle (archiving on a `RunEndEvent`), then calls `envelope.reject(exc)` so the
sender (the target's `await send_event`) receives the exception instead of
deadlocking, and re-raises. The exception exits `run()`, the Controller detects the
failure, and it then [poisons the channel](/reference/events-and-trajectory#eventchannel)
with `set_error()` so no other in-flight `send` hangs.

Use `_dispatch` from any custom `run()`. Advanced optimizers may handle envelopes
directly, but then they own trajectory bookkeeping and the reject-on-error
contract themselves.

## Trajectory access

The base class tracks trajectory history for you:

- `current_trajectory -> ReadableTrajectory | None` the trajectory for the active
  run (a [`FilteredTrajectory`](/reference/events-and-trajectory#trajectory)
  scoped to what the optimizer may see). Set on `RunStartEvent`, cleared on
  `RunEndEvent`, `None` between runs.
- `past_trajectories -> list[ReadableTrajectory]` all completed run trajectories,
  oldest first.

Both are maintained by `_dispatch`. Read feedback either from `event.evaluation`
on the `RunEndEvent` or from these trajectories (the `RunEndEvent` is persisted, so
past runs' feedback is on their trajectories).

## Thread safety

- `envelope.respond()` / `envelope.reject()` are thread-safe (they resolve the
  waiting future via `call_soon_threadsafe`).
- The `EventChannel` and the `Trajectory` are thread-safe, so an optimizer may do
  cross-thread work.
- `on_event` may be called concurrently only if you opt into a parallel `run()`;
  then its own synchronization is your responsibility.

## Design decisions

- **Actor model.** The optimizer is its own concurrent task, not called
  synchronously, so it, not the Controller, owns its consumption strategy.
- **Channel, not method calls.** Events flow over the
  [`EventChannel`](/reference/events-and-trajectory#eventchannel-and-eventenvelope),
  decoupling the optimizer from the target's execution.
- **Lifecycle events, not hooks.** `RunStartEvent` and `RunEndEvent` are ordinary
  events on the same channel, so there are no special methods to override.
- **The base class tracks trajectories.** Most optimizers want run history without
  boilerplate; `_dispatch` provides it, and remains optional for those who want
  full control.
- **No construction config.** All per-run adaptation happens at `initialize()`, so
  arbitrarily many instances can be created identically and adapt themselves to
  the scope they are handed.
