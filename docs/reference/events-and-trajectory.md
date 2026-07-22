---
layout: doc
title: "Events, Channel & Trajectory"
permalink: /reference/events-and-trajectory
---

# Events, Channel & Trajectory

This page specifies how the **target** and the **optimizer** communicate. They
never call each other. They run as two independent concurrent tasks and exchange
typed **events** over an **`EventChannel`**, while everything that happens is
recorded onto a **`Trajectory`**. This is the substrate every other component
sits on.

Three ideas, in order:

1. **Events and responses** are the vocabulary: typed messages with a fixed set
   of valid replies.
2. The **channel** carries the two-way ones; the **trajectory** records them all.
3. **Middleware** is the thin layer where the Controller enforces scope and does
   the recording.

## Events and responses

An **event** is a typed message about something that happened or is about to
happen. An **event response** is the reply to one. Both are frozen
dataclasses defined with `kw_only=True` (keyword-only construction), so
subclasses can add required fields without fighting Python's field-ordering
rules.

### `Event` (base)

Every event carries three fields plus one class-level declaration:

- `event_id: str` a unique id, auto-generated (uuid4).
- `timestamp: datetime` when it was created, auto-generated.
- `security_domain: SecurityDomainTag | None = None` the trust boundary this
  event belongs to. `None` marks a lifecycle event that is not persisted.
- `response_types: ClassVar[tuple[type[EventResponse], ...]] = ()` the responses
  this event class accepts. The **channel validates replies against it** (see
  [`respond`](#eventenvelope) below). An empty tuple means any `EventResponse`
  is accepted.

### `EventResponse` (base)

A response carries exactly one field:

- `event: Event` the event it replies to.

Every response references its event, so the two sides can correlate a reply with
its request even when several are in flight at once.

### The concrete events

There are two families: **controllable** events (two-way, routed to the
optimizer for an answer) and **observable / lifecycle** events (recorded, and in
the lifecycle case answered but carrying no injectable surface).

| Event | Direction | Fired when | Valid responses (`response_types`) |
|-------|-----------|-----------|-------------------------------------|
| `ControllablePreCallEvent` | two-way | the target reaches an injection point and needs a value | `ControllableInjection`, `ControllableNoInjection` |
| `ControllablePostCallEvent` | two-way | the injected value has been used, so the optimizer can observe the effect | `ControllableInjection`, `ControllableNoInjection` |
| `ObservableEvent` | one-way | the target records a fact about the run (a model request, a response, a tool call) | not routed; recorded directly |
| `RunStartEvent` | two-way | just before a run begins | any `EventResponse` |
| `RunEndEvent` | two-way | after the run has been evaluated | `RunEndResponse` |

**Controllable events** carry the `Controllable` they concern plus the current
`request` string (`ControllablePostCallEvent` adds the `answer` that was
produced). Their `security_domain` is **auto-derived** from
`controllable.security_domain` in `__post_init__` if not set explicitly, so a
target never has to tag them by hand.

**`ObservableEvent`** carries an `Observable` and a `content: Any` payload. It is
the one event the target emits **fire-and-forget** (through the `emit` callback,
not the channel); it is recorded straight onto the trajectory and never routed to
the optimizer for a reply. Its `security_domain` auto-derives from the
observable.

**`RunStartEvent`** carries the `trajectory` for the new run (a
[`FilteredTrajectory`](#trajectory) when the recipient is the optimizer).

**`RunEndEvent`** carries `evaluation: EvaluationResult | None` (default `None`).
When the Controller was built with `include_feedback=True` (the default), this is
the scope-filtered evaluation of the run; with `include_feedback=False` it is
`None`. `RunEndEvent` is the one lifecycle event that **is** persisted to the
trajectory, because it carries feedback the optimizer may read from past runs;
its `security_domain` is set by the Controller from the active scope so it passes
trajectory validation.

### The concrete responses

- `ControllableInjection` carries `value: str` (the text to inject) and the
  `controllable` it targets. It is the answer to either controllable event.
- `ControllableNoInjection` carries just the `controllable`. It means "do not
  inject; the target falls back to its own default value." The **Controller
  itself** returns this automatically for any controllable outside the write
  scope, so the optimizer is never even asked about surfaces it cannot inject
  into.
- `RunEndResponse` carries `done: bool = False`. `done=True` tells the Controller
  the optimizer wants to stop (goal reached, or budget spent); `done=False` asks
  for another run.

A single injection type serves both the pre-call and post-call events; the
inherited `event` field tells them apart.

## One run, in sequence

Here is a single run as it crosses the channel. `Controller` steps are the
middleware layer described below.

{% include diagrams/d2.html %}

`RunStartEvent` is **not** recorded (it always sits at a fixed position and
carries the trajectory itself). Every other item, observable events, controllable
events, their responses, and `RunEndEvent`, lands on the trajectory in order.

## `EventChannel` and `EventEnvelope`

The channel is a thread-safe, bidirectional queue. The Controller is on the
**send** side (it forwards the target's two-way events); the optimizer is on the
**receive** side.

Internally the channel is an `asyncio.Queue`, so all queue access happens on the
event-loop thread. Thread safety for the cross-thread operations (`respond`,
`reject`, `close`, `set_error`) comes from bridging onto that thread with
`call_soon_threadsafe`. The interface is deliberately narrow so that a future
process-safe implementation (sockets, multiprocessing) could satisfy the same
contract.

### `EventChannel`

- `await send(event) -> EventResponse` wraps the event in an envelope, enqueues
  it, and waits for the reply. Called from the event-loop thread. Raises if the
  channel has been closed or poisoned.
- `await receive() -> EventEnvelope | None` pulls the next envelope, or `None`
  once the channel is closed and drained.
- `async for envelope in channel` iterates envelopes until close.
- `close()` puts a sentinel so the receive side stops. Idempotent, thread-safe.
- `set_error(error)` **poisons** the channel: it rejects every queued (and
  future) `send` with `error`, then closes. This is how a crash on one side is
  propagated instead of deadlocking the other. Idempotent.

### `EventEnvelope`

An envelope pairs one `event` (public) with the machinery to answer it. The
receiver calls exactly one of:

- `respond(response)` delivers the reply. It first **validates** the response
  against the event's `response_types`; on a mismatch it rejects the envelope and
  raises `TypeError`. Delivery is thread-safe (it resolves the waiting future via
  `call_soon_threadsafe`), and a lock prevents a double answer.
- `reject(error)` delivers an exception to the waiting sender instead of a
  response. Idempotent and a no-op if already answered.

`set_error` (on the channel) and `reject` (on the envelope) are the two halves of
the framework's no-deadlock guarantee: if the optimizer's `on_event` raises, the
envelope is rejected so the target's `await send_event` sees the exception, and
the Controller then poisons the channel so no other in-flight send hangs.

## Trajectory

A **trajectory** is the ordered record of one run: a stream of `Event` and
`EventResponse` objects, which together are the type alias
`TrajectoryItem = Event | EventResponse`. It is the single source of truth for
what happened during a run. There is no separate event log.

### `get_domain(item)`

Every recorded item must be attributable to a security domain. `get_domain` is
the public function that extracts it:

- for an `Event`, it returns `item.security_domain`;
- for an `EventResponse`, it recurses into the event the response replies to.

### `Trajectory` (class, thread-safe)

The producer side pushes items with `emit`; consumers read without blocking.

- `emit(item)` appends an item. It **validates** that `get_domain(item)` is not
  `None`, raising `ValueError` otherwise, so a lifecycle event with no domain
  cannot be persisted. Raises `RuntimeError` if the trajectory is already closed.
- `close()` marks the trajectory finished (no more emits).
- `snapshot()` returns everything emitted so far, without moving the read cursor.
- `drain()` returns everything emitted since the previous `drain()`, and advances
  the cursor. Use it for incremental consumption.

All public methods take a `threading.Lock`, so a target may emit from a worker
thread.

> The `Trajectory` handed to the target's `run()` is not the object itself: the
> target only receives the `emit` callback (typed
> [`EventHandler`](#callback-type-aliases)), so it can record but cannot read or
> close the trajectory.

### `FilteredTrajectory` (class, thread-safe)

The optimizer never sees the full trajectory. It receives a `FilteredTrajectory`:
a read-only view that contains only the items whose security domain is within the
optimizer's scope. It exposes the same non-blocking readers, `snapshot()` and
`drain()`, with its own cursor, and has no `emit` or `close`.

You create one by passing `filtered_scope` to the `Trajectory` constructor and
reaching it via `trajectory.filtered`.

{% include diagrams/d4.html %}

**Push-based, one-way isolation.** Filtering happens once, at `emit` time: when
an in-scope item is emitted, the parent trajectory pushes it into the filtered
view. The `FilteredTrajectory` holds **no reference** to the parent, not as an
attribute, not in a closure. `__slots__` prevents attributes from being attached
later. The parent points to the child, never the reverse. This is a deliberate
security boundary: an optimizer that is handed a `FilteredTrajectory` has no
mechanism to reach the unfiltered data.

`ReadableTrajectory = Trajectory | FilteredTrajectory` is the type alias used
wherever either a full or a filtered trajectory is accepted (for example the
`trajectory` field on `RunStartEvent` and the optimizer's `current_trajectory`).

## Middleware: where scope and recording live

The Controller does not hard-code filtering and recording into its loop. It
wraps the channel's `send` with two small **middleware** functions. A middleware
is a function that takes an event handler and returns a wrapped one:

```python
Middleware = Callable[[EventResponseHandler], EventResponseHandler]
```

`compose(*middlewares)` chains them left-to-right, so the first listed is the
outermost. It is pure function composition: no extra tasks, no extra channels,
no per-call overhead beyond the function calls themselves. The Controller builds
the `send_event` it hands to the target like this:

```python
send_event = compose(
    trajectory_recorder(trajectory),          # outermost: records everything
    security_domain_filter(write_scope),      # inner: declines non-injectable events
)(channel.send)
```

The two built-ins:

- **`trajectory_recorder(trajectory)`** records each event as it passes through,
  then its response once the inner handler returns, straight onto the trajectory.
  It takes no scope: it records regardless of scope, so even a declined event
  stays on the record. In the live wiring this is the two-way traffic on
  `send_event`, that is, the **controllable events and their responses**. (The
  other two recording paths do not go through this middleware: **observable
  events** are recorded because the target's `emit` callback *is* `trajectory.emit`,
  and the controller records the **`RunEndEvent`** onto the trajectory itself after
  evaluation. `RunStartEvent` is never recorded.)
- **`security_domain_filter(scope)`** answers any `ControllablePreCallEvent` /
  `ControllablePostCallEvent` whose controllable is outside `scope` with
  `ControllableNoInjection`, without calling the inner handler (so the optimizer
  is never consulted).

The order matters. Because `trajectory_recorder` is **outermost**, an event
declined by the filter is still recorded, which is exactly what makes a
**read-only** surface work: the Controller passes the **write** scope to the
filter (so a read-only controllable's event is declined), but the recorder still
writes it, and it is within the wider **visibility** scope, so it remains visible
through the optimizer's filtered trajectory. The read-versus-write distinction is
specified in [Security Domains](/reference/security-domains).

> Custom middleware is not a public extension point today. The Controller composes
> this fixed two-stage stack internally. If you need extra behavior (rate
> limiting, tracing), the supported places are inside your target's `run()` or
> your optimizer's `on_event()`.

## Callback type aliases

The target's `run(emit, send_event)` receives its two channels not as objects but
as two callbacks, so it is decoupled from the channel entirely:

- `EventHandler = Callable[[Event], None]` the fire-and-forget `emit`. The target
  calls `emit(ObservableEvent(observable=..., content=...))` to record a fact.
- `EventResponseHandler = Callable[[Event], Awaitable[EventResponse]]` the two-way
  `send_event`. The target `await`s it at a controllable point and uses the
  returned response.

The Controller supplies both, wrapping the channel and the middleware; the target
neither knows nor cares what is on the other end.

## Concurrency model

There is one event loop on one thread ([provided by the
caller](/reference/#the-asyncio-runtime)). On it, the target's `run()` and the
optimizer's `run()` are two separate `asyncio.Task`s. Cooperative scheduling
interleaves them: each yields at its `await` points and the loop advances the
other.

**Target internal parallelism.** A target may itself fan out into concurrent
branches (via `asyncio.gather` or `asyncio.create_task`), each calling
`send_event` independently. Each call creates its own future and suspends only
that branch; other branches continue. This models an AI system that, for example,
issues several tool calls at once.

```python
async def run(self, emit, send_event):
    async def branch_a():
        resp = await send_event(event_a)   # suspends only this branch
        ...
    async def branch_b():
        resp = await send_event(event_b)   # suspends only this branch
        ...
    await asyncio.gather(branch_a(), branch_b())
```

**Bridging blocking work.** A target backed by threads (Docker, a subprocess)
runs its blocking work off the loop and bridges each event back onto it with
`asyncio.run_coroutine_threadsafe`:

```python
async def run(self, emit, send_event):
    loop = asyncio.get_running_loop()
    def blocking_work():
        event = parse_event_from_subprocess(proc)
        future = asyncio.run_coroutine_threadsafe(send_event(event), loop)
        response = future.result()   # blocks this worker thread until the reply
        ...
    await loop.run_in_executor(None, blocking_work)
```

**Optimizer consumption is the optimizer's choice.** The default `run()` consumes
events one at a time. An optimizer may override `run()` to spawn a task per event
(parallel) or to run background work alongside event handling (continuous). The
[Optimizer](/reference/optimizer#consumption-models) page details this.

Because every shared object (trajectory, channel, envelope, LLM client) is
thread-safe, these patterns are safe to combine.
