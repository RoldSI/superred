---
layout: doc
title: "Core Types"
permalink: /reference/types
---

# Core Types

This page catalogs the plain **value types** the framework passes around: goals,
the config and query specs a target declares, controllables and observables,
evaluation scores, and the LLM access types. They are the vocabulary the
interfaces are written in.

Some closely related machinery lives on dedicated pages, because it is more than
a data type:

- the **event and response types**, the **channel**, and the **trajectory** are
  in [Events, Channel & Trajectory](/reference/events-and-trajectory);
- the **security-domain types** (`SecurityDomainTag`, `SecurityDomain`, `Scope`,
  `ScopeResolver`, `scope_includes`) are in
  [Security Domains](/reference/security-domains);
- the **result types** (`RunResult`, `TaskResult`, `ThreatModelResult`) are in
  [Results & Persistence](/reference/results).

Everything here is importable from `superred.core` (and `superred.core.types`).

## Design principles

- **Frozen dataclasses** for immutable value types. Specs, scores, tags, events,
  goals, controllables, and observables cannot be mutated after construction.
- **Runtime-defined over enums.** A `SecurityDomainTag` is a dataclass instance,
  not an enum member, so each target defines its own set at runtime.
- **Required fields over defaults.** A field that is semantically required has no
  default, so an incomplete object cannot be constructed by accident.
- **`kw_only=True` on all event types** to sidestep dataclass field-ordering
  rules across inheritance.
- **No `Any` in public fields** where it can be avoided. The exceptions carry
  genuinely arbitrary payloads (`ObservableEvent.content`, `ObservableValue.content`).

## Goal (`goal.py`)

A frozen dataclass with a single field, `description: str`. It exists as a
dedicated type rather than a bare string so it can later grow structured goal
representations without a breaking change.

```python
Goal(description="Extract the planted secret from the system prompt")
```

## Config and query specs (`state.py`)

A target declares two disjoint sets of interactions: what a **task** sets before
a run, and what an **evaluator** asks after one. They are intentionally separate,
different actors, different lifecycles, different security concerns.

### `ConfigSpec` (frozen)

A pre-run configuration slot. The task fills it via `target.set_config(name,
value)`.

- `name: str` unique within the target.
- `security_domain: SecurityDomainTag` the trust boundary this slot belongs to.
- `description: str` documents the accepted text format. That description is the
  contract between task and target.

Values are always text; the target interprets them.

### `QuerySpec` (frozen)

A post-run interaction the evaluator calls via `target.query(name, **params)`.

- `name: str` unique within the target.
- `description: str` documents what the query does and returns.
- `params: list[QueryParam]` empty for a simple getter; populated for a
  parameterized action (for example "search the database for X").

### `QueryParam` (frozen)

One parameter of a `QuerySpec`: `name: str` and `description: str`.

## Controllable (`controllable.py`)

A frozen dataclass declaring one **injection point**, a surface the optimizer may
inject into.

- `name: str` unique within the target.
- `security_domain: SecurityDomainTag` the trust boundary. Always set;
  a controllable is a concrete injection point that belongs to a domain.
- `description: str = ""` human-readable description.
- `value_type: str = "text"` the expected value type (`"text"`, `"json"`,
  `"modifier"`, `"binary"`).

A `Controllable` is identity-stable and carries no per-call data. The live
request and answer for a given injection live on the
[`ControllablePreCallEvent` / `ControllablePostCallEvent`](/reference/events-and-trajectory#the-concrete-events),
not on the `Controllable`.

## Observable (`observable.py`)

Two frozen types describe **static context** the optimizer may read, facts about
the target that are known before any run and stable across runs (a system prompt,
source code, a tool catalogue). Anything that *happens during* a run belongs on
the trajectory as an `ObservableEvent` instead.

### `Observable` (the spec)

- `name: str` unique within the target.
- `security_domain: SecurityDomainTag` the trust boundary. Always set.
- `description: str = ""`.
- `observable_type: str = "text"` (`"text"`, `"code"`, `"config"`, `"json"`).

### `ObservableValue` (spec plus content)

- `observable: Observable`
- `content: Any = None` the value. A read-only controllable re-presented as an
  observable carries `content=None`, because its value is revealed at runtime on
  the trajectory rather than up front.

`get_observables()` returns `ObservableValue`s; `initialize()` hands them to the
optimizer.

## Evaluation (`evaluation.py`)

The output of judging one run. Produced by a task's `evaluate()`, filtered by the
Controller, and delivered to the optimizer on the `RunEndEvent`.

### `Score` (frozen)

A single named number. **Higher is always better**; the scale is whatever the
task defines.

- `value: float`
- `security_domain: SecurityDomainTag | None = None` which boundary the score
  pertains to. `None` means "always visible" (unscoped). On a `primary_score` it
  **must** be `None`.
- `name: str = "primary"` the dimension name (for example `"asr"`,
  `"utility_degradation"`).

### `EvaluationResult` (frozen)

- `success: bool` whether the adversarial goal was achieved (binary).
- `primary_score: Score` the main optimization signal, always delivered to the
  optimizer (subject only to `include_feedback`).
- `sub_scores: dict[str, Score] = {}` named sub-scores for multi-objective
  analysis, keyed by what each evaluates. Each may carry its own
  `security_domain`.
- `rationale: str = ""` optional free-text explanation.

**Enforced invariant.** `__post_init__` raises `ValueError` if `primary_score`
carries a non-`None` `security_domain`. The primary score is the unscoped signal
that is always delivered; attach security domains to `sub_scores` instead.

How feedback is filtered: two orthogonal controls apply. The Controller's
`include_feedback` flag turns feedback on or off as a whole (the whole
`EvaluationResult`, or `None`). Independently, scope filtering drops only
`sub_scores` whose `security_domain` is out of scope; an untagged sub-score stays,
and the `primary_score`, `success`, and `rationale` are never filtered. This is
detailed in [Security Domains](/reference/security-domains#the-five-filtered-surfaces).

## LLM types (`llm.py`)

These define the optimizer's access to a model. Access and budget are separate:
`LLMConfig` is pure access, and the spending cap is set elsewhere (on the
Controller for the attacker, or on the client for any other caller).

### `LLMConfig` (frozen)

- `model: str` a LiteLLM model identifier (for example `"gpt-4o-mini"`).
- `api_base: str` the API base URL.
- `api_key: str` the provider key.

There is deliberately **no budget field**: the same `LLMConfig` is reused by the
attacker and by judges, each with its own cap or none. Its `__repr__` masks the
key (first four characters plus `...`, or `***` for a short key), so it will not
leak into logs.

### `LLMUsage` (frozen)

Cumulative usage counters: `calls: int = 0` and `cost: float = 0.0` (USD,
computed by `litellm.completion_cost()`). Used throughout the
[result types](/reference/results#result-objects) to report attacker spend.

### `BudgetExhaustedError` (Exception)

Raised when a cost cap is reached. Carries `usage: LLMUsage`, the usage at the
moment of exhaustion.

### `LLMClient` (`core/llm.py`)

The **constrained** async LLM client. The Controller builds one from an
`LLMConfig` and hands it to the optimizer, which reaches it via `self.llm`. The
model, API base, and API key are locked; the optimizer cannot change them.

Constructor: `LLMClient(config, cost_cap_usd=None)`. The cost cap (`None` =
unlimited) is set by whoever builds the client; for the attacker it is the
Controller's `task_cost_cap_usd`. Usage counters are guarded by a
`threading.Lock`.

- `await complete(messages, **kwargs) -> ModelResponse` sends a chat completion
  through litellm (an OpenAI-compatible interface). Behavior worth knowing:
  - `model`, `api_base`, and `api_key` are **stripped** from `kwargs` so they
    cannot be overridden; other kwargs (`temperature`, `max_tokens`, `stop`)
    pass through.
  - Before the call it raises `BudgetExhaustedError` if the cumulative cost has
    reached the cap.
  - After the call it raises `RuntimeError` if the response carries no usage data
    (usage is required for cost tracking).
  - It passes `drop_params=True` to litellm by default, so a sampling parameter a
    given model does not support is dropped rather than raising. A couple of
    provider-specific incompatibilities are handled the same way (for example
    dropping `temperature` for models that reject it alongside `top_p`).
- `usage -> LLMUsage` a thread-safe snapshot of cumulative usage.

An optimizer run without an `llm_config` receives a **noop** client that raises
`BudgetExhaustedError` on any call, so a non-LLM optimizer still satisfies the
`self.llm` contract.
