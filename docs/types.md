# Core Types Reference

## Design Principles

- **Frozen dataclasses** for immutable value types (specs, scores, tags, events, goals).
- **Mutable dataclasses** for stateful types that accumulate data (Controllable, TrajectoryEntry).
- **Runtime-defined over enums**: SecurityDomainTag and TrajectoryEntryType are frozen dataclasses, not enums. Target systems define their own instances at runtime.
- **Required fields over defaults**: Fields that are semantically required have no defaults. This prevents accidental construction of incomplete objects.
- **No `Any` in public fields** where avoidable. `TrajectoryEntry.content` is `Any` because its type is determined by the entry type's `content_type` field.

---

## Goal (`goal.py`)

Frozen dataclass. Currently just `description: str`. Exists as a dedicated type (rather than a raw string) so it can be extended later with structured goal representations.

## State types (`state.py`)

Three intentionally distinct spec types:

### ManualSpec (frozen)

User-provided setup value: `name`, `description`. For secrets, API keys, credentials. Provided by the user through the controller, not by tasks. Example: `ManualSpec("openai_api_key", "OpenAI API key for the target model")`.

### ConfigSpec (frozen)

Pre-run configuration slot: `name`, `security_domain: SecurityDomainTag`, `description`. Used by tasks to set up initial state on the target. The description documents the accepted format — that is the contract between task and target.

### QuerySpec (frozen)

Post-run interaction: `name`, `description`, `params: list[QueryParam]`. Used by the evaluator to query ground-truth state or perform actions after a run. No security domain — this is evaluation data, not an attack surface. Params are empty for simple getters.

### QueryParam (frozen)

A parameter for a QuerySpec: `name`, `description`.

**Design decision**: Manual, config, and query are separate because they have different actors (user, task, evaluator), different lifecycles (once, per-task, post-run), and different security concerns.

## Controllable (`controllable.py`)

### ControllableSpec (frozen)

Declares an injection point: `name`, `security_domain`, `description`, `value_type`, whether `required`.

### Controllable (mutable)

A `ControllableSpec` plus a running `history: list[RequestAnswerPair]`. Mutable because history grows during runs. Passed to the optimizer at initialization and referenced by events during runs.

**Design decision**: Controllable is mutable despite being stored in frozen Event dataclasses. Frozen dataclasses prevent field reassignment, not mutation of contained objects. The Controllable's identity is stable; its history grows.

### RequestAnswerPair (frozen)

A single request-answer interaction with a controllable.

## Observable (`observable.py`)

### Observable (frozen)

Specification of a static observable: `name`, `security_domain`, `description`, `observable_type`.

### ObservableValue (frozen)

An Observable with its content. Passed to optimizer at initialization.

## Event System (`event.py`)

### Event (frozen, kw_only)

Base class. Fields: `event_id` (auto UUID), `timestamp`.

### EventResponse (frozen, kw_only)

Base class. Field: `event: Event` -- every response references the event it was produced for. This is critical for the planned controller architecture where events and responses flow through separate queues and must be correlated.

### ControllablePreCallEvent (frozen, kw_only, extends Event)

Fired when the target reaches a controllable and needs an injection value. Fields: `controllable`, `request` (the current request to the controllable).

### ControllablePostCallEvent (frozen, kw_only, extends Event)

Fired after a controllable's value was used. Fields: `controllable`, `request`, `answer`.

### ControllableInjection (frozen, kw_only, extends EventResponse)

The optimizer's injection. Field: `value: str`. Inherits `event` from EventResponse. Replaces the old `ControllableValue`, `ControllablePreCallResponse`, and `ControllablePostCallResponse`.

### NoModification (frozen, kw_only, extends EventResponse)

Returned by the controller when a controllable event falls outside the active security domain scope. The optimizer is not consulted. Inherits `event` from EventResponse. No extra fields.

### OptimizerDoneEvent (frozen, kw_only, extends Event)

Returned from `Optimizer.post_run()` to signal the optimizer is finished (goal achieved, budget exhausted). The framework stops scheduling runs. Has no extra fields beyond the base Event.

**Design decision**: A single response type for both pre-call and post-call events. The inherited `event` field distinguishes which event type triggered it.

**Design decision**: `kw_only=True` on all event dataclasses. This avoids the Python dataclass inheritance ordering problem (parent has fields with defaults, child has required fields). All construction is keyword-based.

## Trajectory (`trajectory.py`)

### TrajectoryEntryType (frozen)

Runtime-registered type declaring what a trajectory entry contains. All fields required:
- `name`: unique identifier
- `description`: human-readable
- `actor`: which component produces entries of this type (e.g. "AI system", "LLM model")
- `content_type`: Python type of `TrajectoryEntry.content`

Three defaults are always registered: `MODEL_REQUEST`, `MODEL_RESPONSE`, `FEEDBACK`. Targets register additional types at Trajectory construction.

**Design decision**: Actor is on the type, not the entry. All entries of a given type come from the same actor, so it's a property of the type.

**Design decision**: `content_type` is `type[Any]`, meaning it stores an actual Python type (e.g. `str`, `FeedbackResult`, a custom dataclass). This lets consumers validate content at runtime via `isinstance`.

### TrajectoryEntry (mutable)

A single entry: `entry_type`, `content`, `timestamp`. Content shape is determined by `entry_type.content_type`.

Was previously called `TraceEvent` with generic `inputs`/`outputs`/`artifacts` dicts. Renamed and simplified: the entry type now determines what content looks like.

### Trajectory (class, thread-safe)

Stream of TrajectoryEntry objects for one run. Thread-safe via `threading.Lock`.

**Public API**:
- `emit(entry)` -- producer pushes an entry. Raises if closed.
- `close()` -- signals no more entries.
- `drain()` -- returns all entries since last drain, non-blocking. Advances an internal cursor.
- `snapshot()` -- returns all entries so far without advancing cursor.
- `__len__()` -- number of entries.

**Design decision**: Non-blocking only. The previous blocking `async for` pattern was removed. `drain()` is the primary consumption API. `snapshot()` provides read-only access to the full history. Both are thread-safe.

**Design decision**: `drain()` has a single cursor. If multiple threads drain, they share it. The planned controller architecture uses separate Trajectory instances for separate consumers, so this is not a limitation.

## Feedback (`evaluation.py`)

### Score (frozen)

A named numeric score. Higher is always better. Fields: `value: float`, `name: str`.

### EvaluationResult (frozen)

Binary `success` + `primary_score` + optional `sub_scores: dict[str, Score]` + `rationale`.

**Design decision**: `sub_scores` is a dict keyed by what each score evaluates, not a list. This prevents unnamed/unidentifiable scores.

### FeedbackResult (mutable)

Wraps an EvaluationResult. Also a default TrajectoryEntryType (`FEEDBACK`) so feedback flows through the trajectory stream like any other entry.

## Security Domains (`security_domain.py`)

### SecurityDomainTag (frozen)

A node in a domain tree. Fields: `name`, optional `parent`. Not an enum -- fully runtime-defined by the target system.

**Design decision**: Was originally an IntEnum with linear ordering. Changed to support arbitrary tree/forest structures. A target might have:

```
internal
+-- external
|   +-- user
|   +-- api
physical (separate root)
```

`tag.includes(other)` walks from `other` up the ancestor chain to check if it reaches `tag`. This handles the hierarchy: `internal.includes(user)` is True.

### SecurityDomain (immutable class)

A validated, immutable forest of SecurityDomainTag nodes. Construction validates:
- No duplicate tag names.
- Every tag's parent is in the domain (no orphans).

Immutable after construction via `__setattr__`/`__delattr__` overrides.

`distinct_combinations()` generates all antichains (subsets where no tag is an ancestor of another) as a Cartesian product across independent trees. This is the set of distinct security-domain configurations to test.
