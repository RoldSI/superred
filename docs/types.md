# Core Types Reference

## Design Principles

- **Frozen dataclasses** for immutable value types (specs, scores, tags, events, goals).
- **Mutable dataclasses** for stateful types that accumulate data (Controllable, TrajectoryEntry, FeedbackResult).
- **Runtime-defined over enums**: SecurityDomainTag and TrajectoryEntryType are frozen dataclasses, not enums. Target systems define their own instances at runtime.
- **Required fields over defaults**: Fields that are semantically required have no defaults. This prevents accidental construction of incomplete objects.
- **`kw_only=True`** on all event dataclasses to avoid Python's dataclass inheritance ordering problem.
- **No `Any` in public fields** where avoidable. `TrajectoryEntry.content` is `Any` because its type is determined by the entry type's `content_type` field.

---

## Goal (`goal.py`)

Frozen dataclass. Currently just `description: str`. Exists as a dedicated type (rather than a raw string) so it can be extended later with structured goal representations.

## State types (`state.py`)

Two spec types for target configuration and querying:

### ConfigSpec (frozen)

Pre-run configuration slot: `name`, `security_domain: SecurityDomainTag`, `description`. Used by tasks to set up initial state on the target via `target.set_config()`. The description documents the accepted format — that is the contract between task and target.

### QuerySpec (frozen)

Post-run interaction: `name`, `description`, `params: list[QueryParam]`. Used by the evaluator to query ground-truth state or perform actions after a run via `target.query()`. Params are empty for simple getters.

### QueryParam (frozen)

A parameter for a QuerySpec: `name`, `description`.

**Design decision**: Config and query are separate because they have different actors (task vs evaluator), different lifecycles (pre-run vs post-run), and different security concerns.

## Controllable (`controllable.py`)

### ControllableSpec (frozen)

Declares an injection point: `name`, `security_domain: SecurityDomainTag`, `description`, `value_type` (default `"text"`).

### Controllable (mutable)

A `ControllableSpec` plus a running `history: list[RequestAnswerPair]`. Mutable because history grows during runs. Passed to the optimizer at initialization and referenced by events during runs.

**Design decision**: Controllable is mutable despite being stored in frozen Event dataclasses. Frozen dataclasses prevent field reassignment, not mutation of contained objects. The Controllable's identity is stable; its history grows.

### RequestAnswerPair (frozen)

A single request-answer interaction: `request: str`, `answer: str`.

## Observable (`observable.py`)

### Observable (frozen)

Specification of a static observable: `name`, `security_domain: SecurityDomainTag`, `description`, `observable_type` (default `"text"`).

### ObservableValue (frozen)

An Observable paired with its content (`content: Any`). Passed to the optimizer at initialization. Available before execution and stable across runs (e.g. system descriptions, source code, configuration).

## Event System (`event.py`)

All event types use `frozen=True, kw_only=True`.

### Event (base)

Base class for all events. Fields: `event_id: str` (auto UUID), `timestamp: datetime` (auto now).

### EventResponse (base)

Base class for all responses. Field: `event: Event` — every response references the event it was produced for. This enables correlation across the channel.

### ControllablePreCallEvent (extends Event)

Fired when the target reaches a controllable and needs an injection value before proceeding. Fields: `controllable: Controllable`, `request: str`.

### ControllablePostCallEvent (extends Event)

Fired after a controllable's injected value has been used by the target. Informational — lets the optimizer observe the effect. Fields: `controllable: Controllable`, `request: str`, `answer: str`.

### ControllableInjection (extends EventResponse)

The optimizer's injection for a controllable. Field: `value: str`. Returned as the response to `ControllablePreCallEvent` or `ControllablePostCallEvent`.

**Design decision**: A single response type for both pre-call and post-call events. The inherited `event` field distinguishes which event type triggered it.

### NoModification (extends EventResponse)

Returned by the controller when a controllable event falls outside the active security domain scope. The optimizer is not consulted. No extra fields beyond the inherited `event`.

### RunStartEvent (extends Event)

Signals the start of a new target run. Field: `trajectory: Trajectory`. Sent by the controller before `target.run()`. The optimizer's `_dispatch` sets `_current_trajectory` from this.

### RunEndEvent (extends Event)

Signals the end of a target run. Field: `trajectory: Trajectory`. Sent by the controller after `target.run()` completes. The optimizer's `_dispatch` archives the trajectory from this.

### RunEndResponse (extends EventResponse)

Response to `RunEndEvent`. Field: `done: bool = False`. Set `done=True` to signal the optimizer wants to stop (goal achieved, budget exhausted). The controller checks this to decide whether to continue the run loop.

## Event Channel (`channel.py`)

### EventEnvelope

Pairs an event with its response mechanism. Fields: `event: Event` (public), plus internal future and loop reference.

The receiver calls `respond(response)` exactly once to deliver the response back to the sender. Thread-safe — uses `call_soon_threadsafe` to resolve the future on the event loop thread, and a `threading.Lock` to prevent double-respond.

### EventChannel

Thread-safe bidirectional event-response channel.

**Send side** (controller → optimizer):
- `send(event) -> EventResponse` — creates a future, wraps event + future in an `EventEnvelope`, puts on internal `asyncio.Queue`, awaits future. Must be called from the event loop thread.

**Receive side** (optimizer):
- `receive() -> EventEnvelope | None` — pulls next envelope from queue. Returns `None` when channel is closed and all envelopes consumed.
- `async for envelope in channel` — iterates envelopes until closed (raises `StopAsyncIteration` on `None`).

**Lifecycle**:
- `close()` — thread-safe. Puts a sentinel (`None`) on the queue. Uses `call_soon_threadsafe` if called from another thread, `put_nowait` if no event loop has been captured yet. Idempotent.

**Design decision**: Uses `asyncio.Queue` internally — all queue access happens on the event loop thread. Thread safety for `respond()` and `close()` comes from `call_soon_threadsafe` bridging. The interface is designed so a future process-safe implementation (multiprocessing, sockets) can provide the same contract.

**Location**: `core/channel.py` (not in `types/` — it's communication infrastructure, not a data type).

## Middleware (`middleware.py`)

Composable transformations on the `EventHandler` callback. Zero overhead — pure function composition, no extra tasks or channels.

### Middleware type

`Middleware = Callable[[EventHandler], EventHandler]` — takes a handler, returns a wrapped handler.

### compose(*middlewares)

Composes middleware left-to-right (first listed = outermost). `compose(a, b)(handler)` means `a(b(handler))`: events pass through `a` first, then `b`, then the inner handler.

### security_domain_filter(scope, event_log, event_log_lock)

Built-in middleware that filters controllable events by security domain. Events for controllables outside `scope` are answered with `NoModification` without reaching the inner handler. Optionally logs all event-response pairs to `event_log` (thread-safe via `event_log_lock`).

**Design decision**: Middleware is function composition, not channel pipes. Each middleware wraps the callback — no background tasks, no extra channels, no sentinel cleanup. This gives the composability of pipeline architectures with zero overhead.

**Location**: `core/middleware.py`.

## Trajectory (`trajectory.py`)

### TrajectoryEntryType (frozen)

Runtime-registered type declaring what a trajectory entry contains. All fields required:
- `name: str` — unique identifier.
- `description: str` — human-readable description.
- `actor: str` — which component produces entries of this type (e.g. `"AI system"`, `"LLM model"`, `"task evaluator"`).
- `content_type: type[Any]` — the Python type that `TrajectoryEntry.content` must be.

Three defaults are always registered: `MODEL_REQUEST` (str), `MODEL_RESPONSE` (str), `FEEDBACK` (FeedbackResult). Targets register additional types at Trajectory construction.

**Design decision**: Actor is on the type, not the entry. All entries of a given type come from the same actor.

**Design decision**: `content_type` stores an actual Python type (e.g. `str`, `FeedbackResult`). Consumers can validate content at runtime via `isinstance`.

### TrajectoryEntry (mutable)

A single entry: `entry_type: TrajectoryEntryType`, `content: Any`, `timestamp: datetime`. Content shape is determined by `entry_type.content_type`.

### Trajectory (class, thread-safe)

Stream of TrajectoryEntry objects for one run. Thread-safe via `threading.Lock` on all public methods.

**Public API**:
- `emit(entry)` — producer pushes an entry. Raises `RuntimeError` if closed.
- `close()` — signals no more entries will be emitted.
- `drain()` — returns all entries since last drain, non-blocking. Advances an internal cursor.
- `snapshot()` — returns all entries so far without advancing cursor.
- `__len__()` — number of entries emitted.

**Design decision**: Non-blocking consumption only. `drain()` is cursor-based for incremental reading. `snapshot()` provides full history. Both are thread-safe.

## Evaluation (`evaluation.py`)

### Score (frozen)

A named numeric score. Higher is always better. Fields: `value: float`, `name: str` (default `"primary"`).

### EvaluationResult (frozen)

The result of evaluating one run:
- `success: bool` — whether the adversarial goal was achieved (binary).
- `primary_score: Score` — the main score for optimization.
- `sub_scores: dict[str, Score]` — named sub-scores for multi-objective analysis (default empty).
- `rationale: str` — optional free-text explanation from the evaluator (default empty).

**Design decision**: `sub_scores` is a dict keyed by what each score evaluates, not a list. This prevents unnamed/unidentifiable scores.

### FeedbackResult (mutable)

Wraps an `EvaluationResult`. Field: `evaluation: EvaluationResult`. This is the content type for the `FEEDBACK` TrajectoryEntryType, so evaluation results flow through the trajectory stream like any other entry.

## Security Domains (`security_domain.py`)

### SecurityDomainTag (frozen)

A node in a domain tree. Fields: `name: str`, `parent: SecurityDomainTag | None` (default `None` for roots). Not an enum — fully runtime-defined by the target system.

`tag.includes(other)` walks from `other` up the ancestor chain to check if it reaches `tag`. Example: `internal.includes(user)` is `True` because `user` is a descendant of `internal`.

A target might define:
```
internal
├── external
│   ├── user
│   └── api
physical (separate root)
```

### SecurityDomain (immutable class)

A validated, immutable forest of SecurityDomainTag nodes. Construction validates:
- No duplicate tag names.
- Every tag's parent is in the domain (no orphans — raises `ValueError`).

Immutable after construction via `__setattr__`/`__delattr__` overrides.

**Properties**:
- `roots` — tags with no parent.

**Methods**:
- `distinct_combinations()` — generates all antichains (subsets where no tag is an ancestor of another) as a Cartesian product across independent trees. This is the set of distinct security-domain scopes to test. Includes the empty set.
