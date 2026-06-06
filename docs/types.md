# Core Types Reference

## Design Principles

- **Frozen dataclasses** for immutable value types (specs, scores, tags, events, goals, controllables, observables).
- **Runtime-defined over enums**: SecurityDomainTag is a frozen dataclass, not an enum. Target systems define their own instances at runtime.
- **Required fields over defaults**: Fields that are semantically required have no defaults. This prevents accidental construction of incomplete objects.
- **`kw_only=True`** on all event dataclasses to avoid Python's dataclass inheritance ordering problem.
- **No `Any` in public fields** where avoidable. `ObservableEvent.content` is `Any` because it carries arbitrary target-side data.

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

### Controllable (frozen)

Declares an injection point: `name`, `security_domain: SecurityDomainTag` (must not be `None`), `description`, `value_type` (default `"text"`). Frozen and identity-stable; per-call request/answer data lives on `ControllablePreCallEvent` / `ControllablePostCallEvent` rather than on the `Controllable` itself.

## Observable (`observable.py`)

### Observable (frozen)

Specification of a static observable: `name`, `security_domain: SecurityDomainTag`, `description`, `observable_type` (default `"text"`).

### ObservableValue (frozen)

An Observable paired with its content (`content: Any`). Passed to the optimizer at initialization. Available before execution and stable across runs (e.g. system descriptions, source code, configuration).

## Event System (`event.py`)

All event types use `frozen=True, kw_only=True`.

### Event (base)

Base class for all events. Fields: `event_id: str` (auto UUID), `timestamp: datetime` (auto now), `security_domain: SecurityDomainTag | None = None`.

### EventResponse (base)

Base class for all responses. Field: `event: Event` — every response references the event it was produced for. This enables correlation across the channel.

### ControllablePreCallEvent (extends Event)

Fired when the target reaches a controllable and needs an injection value before proceeding. Fields: `controllable: Controllable`, `request: str`. The `security_domain` is auto-derived from `controllable.security_domain` via `__post_init__`.

### ControllablePostCallEvent (extends Event)

Fired after a controllable's injected value has been used by the target. Informational — lets the optimizer observe the effect. Fields: `controllable: Controllable`, `request: str`, `answer: str`. The `security_domain` is auto-derived from `controllable.security_domain` via `__post_init__`.

### ControllableInjection (extends EventResponse)

The optimizer's injection for a controllable. Fields: `value: str`, `controllable: Controllable`. Returned as the response to `ControllablePreCallEvent` or `ControllablePostCallEvent`.

**Design decision**: A single response type for both pre-call and post-call events. The inherited `event` field distinguishes which event type triggered it.

### ControllableNoInjection (extends EventResponse)

Returned by the controller when a controllable event falls outside the active security domain scope. The optimizer is not consulted. Fields: `controllable: Controllable`, plus the inherited `event`.

### ObservableEvent (extends Event)

One-way observation event emitted by the target to record information in the trajectory. Fields: `observable: Observable`, `content: Any`. Used for target-side logging (e.g. model requests, model responses). `security_domain` auto-derives from the observable via `__post_init__` if not set explicitly.

### RunStartEvent (extends Event)

Signals the start of a new target run. Field: `trajectory: ReadableTrajectory`. When sent to the optimizer, this is a `FilteredTrajectory` (only entries within the security domain scope are visible). The optimizer's `_dispatch` sets `_current_trajectory` from this.

### RunEndEvent (extends Event)

Signals the end of a target run. Sent after evaluation. Field: `evaluation: EvaluationResult | None` (default `None`). Persisted to the trajectory (unlike `RunStartEvent`). The `security_domain` is set from the active scope (required for trajectory validation). When `Controller(include_feedback=True)` (the default), `evaluation` carries the filtered `EvaluationResult`; when `include_feedback=False`, `evaluation` is `None`. The optimizer reads feedback directly from `event.evaluation`, or from past trajectories. The optimizer's `_dispatch` archives the current trajectory on this event.

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
- `close()` — thread-safe. Puts a sentinel (`None`) on the queue. Uses `call_soon_threadsafe` if an event loop has been bound, `put_nowait` otherwise. Idempotent.

**Design decision**: Uses `asyncio.Queue` internally — all queue access happens on the event loop thread. Thread safety for `respond()` and `close()` comes from `call_soon_threadsafe` bridging. The interface is designed so a future process-safe implementation (multiprocessing, sockets) can provide the same contract.

**Location**: `core/channel.py` (not in `types/` — it's communication infrastructure, not a data type).

## Middleware (`middleware.py`)

Composable transformations on the `EventResponseHandler` callback. Zero overhead — pure function composition, no extra tasks or channels.

### Middleware type

`Middleware = Callable[[EventResponseHandler], EventResponseHandler]` — takes a handler, returns a wrapped handler.

### compose(*middlewares)

Composes middleware left-to-right (first listed = outermost). `compose(a, b)(handler)` means `a(b(handler))`: events pass through `a` first, then `b`, then the inner handler.

### security_domain_filter(scope)

Built-in middleware that filters controllable events by security domain. Events for controllables outside `scope` are answered with `ControllableNoInjection` without reaching the inner handler.

### trajectory_recorder(trajectory)

Built-in middleware that records events and responses directly to the trajectory. Takes only a `trajectory` parameter (no scope). Records `Event` and `EventResponse` objects as they pass through. `RunStartEvent` is NOT persisted. `RunEndEvent` IS persisted (it carries the evaluation result and has `security_domain` set from the scope).

**Design decision**: Middleware is function composition, not channel pipes. Each middleware wraps the callback — no background tasks, no extra channels, no sentinel cleanup. This gives the composability of pipeline architectures with zero overhead.

**Location**: `core/middleware.py`.

## Trajectory (`trajectory.py`)

The trajectory stores `Event | EventResponse` objects directly -- there is no `TrajectoryEntry` or `TrajectoryEntryType` wrapper. Events carry their own `security_domain`, and `EventResponse` objects derive theirs from the referenced event.

### get_domain(item)

Public function that extracts `security_domain` from a trajectory item. For `Event`, returns `item.security_domain` directly. For `EventResponse`, recurses via `get_domain(item.event)`.

### Trajectory (class, thread-safe)

Stream of `Event | EventResponse` objects for one run. Thread-safe via `threading.Lock` on all public methods.

**Public API**:
- `emit(item)` — producer pushes an Event or EventResponse. Validates that `get_domain(item)` is not `None` (every trajectory item must have a security domain). Raises `RuntimeError` if closed.
- `close()` — signals no more items will be emitted.
- `drain()` — returns all items since last drain, non-blocking. Advances an internal cursor.
- `snapshot()` — returns all items so far without advancing cursor.
- `__len__()` — number of items emitted.

**Design decision**: Non-blocking consumption only. `drain()` is cursor-based for incremental reading. `snapshot()` provides full history. Both are thread-safe.

### FilteredTrajectory (class, thread-safe)

Read-only view of trajectory items within a security domain scope. Created by passing ``filtered_scope`` to the :class:`Trajectory` constructor, accessed via ``trajectory.filtered``.

**Public API**:
- `snapshot()` — returns all in-scope items received so far.
- `drain()` — returns in-scope items received since last drain. Maintains its own cursor.

No `emit()` or `close()` — read-only. Uses `__slots__` to prevent `__dict__`.

**Push-based encapsulation**: Items are pushed from Trajectory to FilteredTrajectory at emit time. FilteredTrajectory holds **no reference** to the underlying Trajectory — not as an attribute, not in a closure, nowhere. This is a deliberate security boundary: the optimizer receives a FilteredTrajectory and cannot reach the unfiltered data through any mechanism.

**Design decision**: Push-based rather than pull-based. Filtering happens once at emit time (efficient). The Trajectory holds a reference to its filtered view (parent --> child), but the reverse direction is impossible. `__slots__` prevents arbitrary attribute injection. The scope is specified at Trajectory construction time -- no post-hoc subscription machinery needed.

### ReadableTrajectory (type alias)

`ReadableTrajectory = Trajectory | FilteredTrajectory` — used in event types and optimizer annotations where either a full or filtered trajectory is accepted.

### EventHandler / EventResponseHandler (type aliases)

Defined in `event.py`:
- `EventHandler = Callable[[Event], None]` — fire-and-forget callback for one-way events. Passed to `target.run(emit, ...)`; the target calls `emit(ObservableEvent(observable=..., content=...))`. This restricts the target to only emitting, without access to reading or closing the trajectory.
- `EventResponseHandler = Callable[[Event], Awaitable[EventResponse]]` — two-way callback at controllable points. Passed to `target.run(..., send_event)`; the target awaits `send_event(ControllablePreCallEvent(...))` and uses the response.

## Evaluation (`evaluation.py`)

### Score (frozen)

A named numeric score. Higher is always better. Fields: `value: float`, `security_domain: SecurityDomainTag | None`, `name: str` (default `"primary"`). The security domain tags a sub-score to a scope; `None` means the score is always visible regardless of scope. The controller filters `sub_scores` by the active scope (dropping only out-of-scope ones) before attaching the evaluation to `RunEndEvent`. The `primary_score` carries no `security_domain` and is never filtered.

### EvaluationResult (frozen)

The result of evaluating one run:
- `success: bool` — whether the adversarial goal was achieved (binary).
- `primary_score: Score` — the main score for optimization.
- `sub_scores: dict[str, Score]` — named sub-scores for multi-objective analysis (default empty).
- `rationale: str` — optional free-text explanation from the evaluator (default empty).

**Design decision**: `sub_scores` is a dict keyed by what each score evaluates, not a list. This prevents unnamed/unidentifiable scores. Each sub-score carries a `security_domain`; the controller filters sub_scores by the active scope before attaching the evaluation to `RunEndEvent`, dropping only those with an out-of-scope domain (an untagged sub-score, `security_domain=None`, is always visible), so the optimizer only sees scores within its security domain. `primary_score` carries no `security_domain` and is never filtered: it is the unscoped optimization signal, always included.

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

## LLM Types (`llm.py`)

### LLMConfig (frozen)

Configuration for controller-mediated LLM access. Part of the threat model. Fields: `model: str`, `api_base: str`, `api_key: str`, `max_cost: float | None` (default `None` — unlimited).

The `__repr__` masks the API key (shows first 4 chars + `...`, or `***` for short keys).

**Design decision**: Frozen because the LLM configuration is an experiment parameter that must not change during execution. `max_cost` is optional — `None` means unlimited. Cost is computed per call via `litellm.completion_cost()`.

### LLMUsage (frozen)

Cumulative LLM usage counters. Fields: `calls: int` (default 0), `cost: float` (default 0.0, USD computed via `litellm.completion_cost()`).

Used in `RunResult.llm_usage` (cumulative snapshot after each run) and `TaskResult.llm_usage` (total for the task).

### BudgetExhaustedError (Exception)

Raised by `LLMClient` when the cost budget is exhausted. Fields: `usage: LLMUsage` — the usage at the time of exhaustion. Inherits from `Exception`.

## LLM Client (`core/llm.py`)

### LLMClient

Constrained async LLM client. Created by the controller from an `LLMConfig` and passed to the optimizer. The model, API base, and API key are locked — the optimizer cannot change them. Thread-safe: usage counters are protected by `threading.Lock`.

**Public API**:
- `complete(messages, **kwargs) -> ModelResponse` — send a chat completion via litellm. `model`, `api_base`, `api_key` are stripped from kwargs. Raises `BudgetExhaustedError` before the call if the cost budget is exhausted. Raises `RuntimeError` if the response is missing usage data (usage reporting is required for cost tracking).
- `usage -> LLMUsage` — current cumulative usage (thread-safe snapshot).

**Design decision**: Uses litellm internally so the optimizer gets an OpenAI-compatible interface (standard chat completions format). The client strips locked keys from kwargs rather than raising — this prevents accidental override while allowing kwargs passthrough for parameters like `temperature`, `max_tokens`, `stop`.

---

### SecurityDomain (immutable class)

A validated, immutable forest of SecurityDomainTag nodes. Construction validates:
- No duplicate tag names.
- Every tag's parent is in the domain (no orphans — raises `ValueError`).

Immutable after construction via `__setattr__`/`__delattr__` overrides.

**Properties**:
- `roots` — tags with no parent.

**Methods**:
- `distinct_combinations()` — generates all antichains (subsets where no tag is an ancestor of another) as a Cartesian product across independent trees. Returns `list[frozenset[SecurityDomainTag]]` (i.e., `list[Scope]`). This is the set of distinct security-domain scopes to test. Includes the empty set.

### Scope (type alias)

`Scope = frozenset[SecurityDomainTag]` — a set of tags representing a multi-tag attack surface scope. The controller uses scopes to filter all optimizer inputs. `scope_includes(scope, tag)` returns `True` if any tag in the scope includes the target tag (via `SecurityDomainTag.includes()`).

### scope_includes (function)

`scope_includes(scope: Scope, tag: SecurityDomainTag) -> bool` — helper that checks whether a security domain tag falls within a scope. Returns `True` if `any(s.includes(tag) for s in scope)`.
