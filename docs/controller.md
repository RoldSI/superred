# Controller

The controller is the main orchestrator for red-teaming evaluations. One `Controller` instance evaluates one security claim against one threat model — a single `(scope, llm_config)` combination. Sweeping multiple threat models is the caller's job: instantiate one `Controller` per combination and run them sequentially or via `asyncio.gather`.

## Construction

```python
from superred.core.controller import Controller, TargetFactory
from superred.core.types.llm import LLMConfig
from superred.core.types.security_domain import Scope

# Produces fresh target instances; declares how many tasks may run in
# parallel against independent instances.
target_factory = TargetFactory(
    create=lambda: MyTarget(api_key="sk-..."),  # manual values at construction
    concurrency=8,                              # default is 1 (sequential)
)
claim = SecurityClaim.from_tasks([task_a, task_b])

llm_config = LLMConfig(
    model="gpt-4o-mini",
    api_base="https://api.openai.com",
    api_key="sk-...",
    max_cost=5.00,  # USD budget limit (optional, None = unlimited)
)

scope: Scope = frozenset({external_tag})

controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),  # fresh optimizer per task
    target_factory=target_factory,            # fresh target per task; bounded concurrency
    security_claim=claim,
    scope=scope,                              # read & write surface (visible + injectable)
    read_only=frozenset(),                    # optional: visible-but-not-injectable tags
    llm_config=llm_config,                    # optional — omit for non-LLM optimizers
    max_runs_per_task=100,                    # safety limit, default 100
    include_feedback=True,                    # populate RunEndEvent.evaluation (default True)
    results_dir="results/run-1",              # optional — persist threat-model JSON
)
# `scope` is what the attacker can read AND write; `read_only` adds tags it
# can only read. To see the whole system but inject only the prompt:
#   Controller(scope=frozenset({prompt_tag}),
#              read_only=frozenset({system_tag}), ...)

tmr = await controller.run()  # -> ThreatModelResult
```

### `scope` may be a fixed `Scope` or a per-task `ScopeResolver`

`scope` accepts either a fixed `Scope` (the classic behavior above, one read & write surface applied to every task) **or** a `ScopeResolver` (a `Callable[[Task], Scope]`, exported as `superred.core.ScopeResolver`) that computes the read & write scope **once per task**. `callable(scope)` is the discriminator. `read_only` independently accepts the same two forms (a fixed `Scope` or a `ScopeResolver`), resolved separately per task; the two resolvers are unrelated.

```python
from superred.core import ScopeResolver
from my_target import DB_ORDERS_TAG, DB_CUSTOMERS_TAG

def resolve(task: Task) -> Scope:
    # grant each task exactly the surface its goal needs
    if task.goal.description.startswith("orders:"):
        return frozenset({DB_ORDERS_TAG})
    return frozenset({DB_CUSTOMERS_TAG})

controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),
    target_factory=target_factory,
    security_claim=claim,
    scope=resolve,             # a ScopeResolver, not a frozenset
    scope_label="per-goal",    # REQUIRED in dynamic mode (see below)
)
```

- **`scope_label` is required in dynamic mode.** When **either** `scope` or `read_only` is callable, `scope_label` must be a non-empty `str` (else `ValueError` at construction). It names the run, since there is no single concrete scope to name it by. When **both** are fixed `frozenset`s, `scope_label` must be `None` (else `ValueError`), and the existing non-empty `(scope | read_only)` check still applies.
- **A resolver may skip a task.** Either resolver raising `NotApplicable` contributes an empty set for its own dimension, exactly like returning `frozenset()`. The task is skipped (lands in `ThreatModelResult.skipped_tasks`, the same channel as `task.configure_target` skips) when the resolved visibility (`scope | read_only`) is empty: no tag is granted in either dimension. Any tag (read or write, from either resolver) means the task runs (e.g. `scope` `NotApplicable` but `read_only` non-empty yields a read-only-only run with no injectable controllables). Use this when a task has no meaningful surface.
- **A resolver failure is contained per task.** If a resolver raises any exception *other* than `NotApplicable`, that one task becomes a contained error: `TaskResult.stop_reason == "error"`, `TaskResult.error` set, and sibling tasks are unaffected, so the threat model is not aborted.
- **Return the target's exported tag singletons.** Scope matching is by identity, so the resolver MUST return the same `SecurityDomainTag` instances the target exposes (import them from the target module). A freshly constructed tag with the same `name`/`parent` will not match and will gate everything out.

The resolved scope gates **all** optimizer-facing surfaces for that task: the injectable controllables list, the observables list, read-only controllables re-presented as observables, the `FilteredTrajectory` view, the `security_domain_filter` (inject vs `ControllableNoInjection`), the feedback `sub_scores` filter, and the `RunEndEvent.security_domain`.

For single-instance targets (tests, expensive-to-construct resources), use
the `TargetFactory.singleton(target)` classmethod — concurrency is locked
to 1 since a shared instance can't safely serve parallel tasks. The
controller still calls `target.teardown()` once per task, so a multi-task
singleton needs an idempotent teardown.

The controller does not create an asyncio event loop — the caller provides it via `asyncio.run()` or an existing loop.

Sweeping multiple threat models:

```python
import asyncio, itertools

results = await asyncio.gather(*(
    Controller(
        scope=s, llm_config=c,
        optimizer_factory=..., target_factory=target_factory,
        security_claim=claim,
    ).run()
    for s, c in itertools.product(scopes, configs)
))
```

## Run lifecycle

`await controller.run() -> ThreatModelResult` runs every task in the security claim against the configured `(scope, llm_config)`. Tasks run concurrently bounded by `target_factory.concurrency` (`asyncio.Semaphore` + `asyncio.gather`); results are collected in input order.

For each task:

1. `target = target_factory.create()` — fresh `Target` instance owned by this task.
2. `task.configure_target(target)` — if `NotApplicable`, the task is collected into `skipped_tasks` and not retried.
3. Create `LLMClient` from `llm_config` (fresh per task — budget is per-task). If no `llm_config`, use a noop client.
4. Create fresh optimizer via `optimizer_factory()`.
5. `optimizer.initialize(goal, filtered_controllables, filtered_observables, llm_client)` — only controllables and observables within the scope are passed.
6. Create `EventChannel`, launch `optimizer.run(channel)` as concurrent `asyncio.Task`.
7. **Run loop** (until optimizer signals done or `max_runs_per_task`):
   - Create `Trajectory(filtered_scope=scope)`. Access `trajectory.filtered` for the optimizer's view.
   - Send `RunStartEvent(filtered_trajectory)` through the channel.
   - `target.run(emit, send_event)` — target emits `ObservableEvent` instances; `send_event` bridges to channel with security domain filtering. The `trajectory_recorder` middleware records events and responses directly to the trajectory.
   - `task.evaluate(trajectory, target)` — returns `EvaluationResult`; controller filters `sub_scores` by scope.
   - Send `RunEndEvent(evaluation=filtered_eval, security_domain=<scope_tag>)` through the channel; it is persisted to the trajectory. When `include_feedback=True` (default) the evaluation is attached.
   - Close the trajectory; call `target.reset_ephemeral_state()` to reset ephemeral state for the next run within this task.
   - Track best score / success across runs.
   - On exception inside the run: the partial trajectory is preserved as a final `RunResult` with a zero-score evaluation; the formatted exception lands on `TaskResult.error`; `stop_reason = "error"`; loop ends.
8. Close channel, await optimizer task, `optimizer.teardown()`. Final `target.reset_ephemeral_state()` (in `finally`) followed by `target.teardown()`; the per-task target instance is then discarded.

As each task finishes, its per-task detail JSON is written immediately (when `results_dir` is set), so an interrupted run still leaves every completed task on disk. After all tasks finish, the claim-level summary file is written as a completion marker, the controller prints a summary to stdout, and returns the `ThreatModelResult`.

### Internal structure

- `_iterate_tasks(scope, llm_config)` — runs the security claim with `asyncio.Semaphore(target_factory.concurrency)` + `asyncio.gather`. Each in-flight task acquires the semaphore, calls `target_factory.create()`, runs the task, then `target.teardown()` in `finally` before releasing the slot. Results are reassembled in input order.
- `_run_task(task, scope, llm_config, target)` — manages the per-task lifecycle: configure, create fresh optimizer, initialize, build middleware stack, run loop, collect results.
- `_run_single(task, target, channel, scope, run_number, trajectory)` — executes one iteration. The trajectory is owned by `_run_task` so a partial trajectory survives an exception. Returns `(evaluation, done)`.

The `send_event` callback passed to `target.run` is built by composing middleware onto `channel.send`:
```python
send_event = compose(
    trajectory_recorder(trajectory),
    security_domain_filter(write_scope),
)(channel.send)
```

The filter receives the **read & write scope** (the controller's `scope`); all other filtering uses the full visibility scope (`scope | read_only`). When `read_only` is empty the two are identical.

Users can add custom middleware (logging, tracing, budget enforcement) by extending the composition.

## Security domain filtering

The controller enforces the security domain scope across **all optimizer inputs**:

1. **Controllables**: Only the **injectable** ones are passed to `optimizer.initialize()` — filtered with `scope_includes(write_scope, c.security_domain)` (the read & write `scope`). Out-of-scope and read-only controllables are not in this list, so it means exactly "what the optimizer can inject into."
2. **Observables**: Filtered with `scope_includes(visibility, o.observable.security_domain)` before `optimizer.initialize()`, **plus** each read-only controllable (visible but not injectable) re-presented as an `ObservableValue` (with `content=None`, since its value is revealed at runtime on the trajectory). So `observables` means "what the optimizer can read," including read-only controllables. Out-of-scope observables are never exposed.
3. **Events**: `ControllablePreCallEvent` and `ControllablePostCallEvent` for out-of-scope controllables are answered with `ControllableNoInjection` without reaching the optimizer. Implemented as the `security_domain_filter` middleware composed onto `channel.send`. The filter is given the **read & write `scope`**, so controllable events under `read_only` tags — visible but not injectable — are declined the same way. The difference from out-of-scope events is visibility: a read-only event is inside the full visibility scope, so it (and its `ControllableNoInjection`) remains visible through the filtered trajectory, observables, and feedback.
4. **Trajectory**: The optimizer receives a `FilteredTrajectory` (via `RunStartEvent`) that only exposes items within the security domain scope.
5. **Feedback**: Each `sub_score` in the `EvaluationResult` carries a `security_domain`. The controller filters `sub_scores`, dropping only those whose `security_domain` is out of scope (an untagged sub-score, `security_domain=None`, is always visible). The `RunEndEvent` carries the filtered evaluation directly (when `include_feedback=True`, the default) and is persisted to the trajectory with `security_domain` set to a tag from the scope. The `primary_score` carries no `security_domain` and is never filtered; it, `success`, and `rationale` are always included (the optimizer needs the main optimization signal). The optimizer reads feedback from `event.evaluation` on `RunEndEvent`, or from past trajectories.

A `Scope` is a `frozenset[SecurityDomainTag]`. `scope_includes(scope, tag)` returns `True` if ANY tag in the scope includes the target tag. This allows testing specific security boundaries — scoping to `{external_tag}` tests only external-facing surfaces, while scoping to `{root_tag}` tests everything.

Access level is a property of the scope, not of each tag. The controller takes two sets: `scope` (read & write — visible and injectable) and an optional `read_only` set (visible only). `read_only` defaults to empty, so the whole `scope` is read & write — the classic behavior. To make part of the surface read-only, list it under `read_only` instead: `Controller(scope={prompt}, read_only={system})` lets the attacker see the whole `system` subtree but inject only into `prompt`. A `read_only` tag already covered by `scope` has no effect (read & write overrules — only `scope` drives the injection check, so it stays injectable); `scope` and `read_only` cannot both be empty. Internally only the injection check (item 3) uses `scope`; items 1, 2, 4, 5 and the `FilteredTrajectory` use the full visibility scope `scope | read_only`, so read-only information flows through the exact same recording mechanism as read & write surfaces.

## Unified trajectory as event log

There is no separate event log. The `trajectory_recorder` middleware records all events and responses directly into the trajectory as `Event | EventResponse` objects:

- **Controllable events** — `ControllablePreCallEvent`, `ControllablePostCallEvent`.
- **Controllable responses** — `ControllableInjection`, `ControllableNoInjection`.
- **Observable events** — `ObservableEvent` emitted by the target (model requests, model responses, etc.).
- **RunEndEvent** — persisted to the trajectory by the controller after evaluation. Carries `evaluation: EvaluationResult | None` and has `security_domain` set from the scope.

The trajectory IS the event log. `RunStartEvent` is NOT persisted to the trajectory — it carries no additional information and always appears at a fixed position. `RunEndEvent` IS persisted because it carries the evaluation result. To inspect events and responses for a run, query the trajectory items by type.

## Result types

### RunResult (frozen)

One target execution + evaluation:
- `trajectory: Trajectory` — the run trajectory.
- `evaluation: EvaluationResult` — the evaluation result for this run.
- `llm_usage: LLMUsage` — cumulative optimizer LLM usage after this run. This is a cumulative snapshot — each successive run includes all prior usage, enabling budget-vs-performance tracking.

### TaskResult (frozen)

All runs for one task:
- `task: Task[Target]` — the task that was evaluated.
- `runs: list[RunResult]` — all run results, in order.
- `best_score: Score` — highest primary score across all runs.
- `best_evaluation: EvaluationResult` — the evaluation that produced the best score.
- `success: bool` — whether any run achieved the adversarial goal.
- `llm_usage: LLMUsage` — total optimizer LLM usage across all runs.
- `stop_reason: Literal["done", "max_runs", "budget_exhausted", "error"]` — why the run loop ended: optimizer signaled `RunEndResponse(done=True)`, hit `max_runs_per_task`, `BudgetExhaustedError` was raised, or an unexpected exception escaped the optimizer/target/evaluator and the task was abandoned.
- `scope: Scope` (default `frozenset()`): the read & write scope enforced for **this** task. In static mode it equals the controller's `scope` for every task; with a `ScopeResolver` it is the per-task resolved scope.
- `read_only: Scope` (default `frozenset()`): the read-only scope enforced for **this** task. In static mode it equals the controller's `read_only` for every task; with a `ScopeResolver` it is the per-task resolved read-only scope.
- `error: str | None`: formatted exception (type + message + traceback) when something went wrong, `None` otherwise. Set whenever the controller observes an exception associated with the task. Most commonly populated with `stop_reason="error"`, but also populated as a bonus diagnostic when the run loop classified the task cleanly (`"done"` / `"max_runs"` / `"budget_exhausted"`) yet the optimizer task subsequently raised during teardown. Consumers should treat `error` and `stop_reason` as independent fields: `error is not None` does not imply `stop_reason == "error"`, and vice versa is the common (but not required) case.

### ThreatModelResult (frozen)

Results for one (scope, llm_config) combination:
- `scope: Scope`: the visibility scope tested. **In dynamic mode (a `ScopeResolver`) this is an empty frozenset**; the per-task truth lives on each `TaskResult.scope`.
- `read_only: Scope`: extra visible-but-not-injectable tags (empty for an all-read & write run; also empty in dynamic mode).
- `scope_label: str | None` (default `None`): `None` in static mode (unchanged); in dynamic mode it is the label passed to the controller and names the run (since `scope`/`read_only` are empty here).
- `llm_config: LLMConfig | None` — the LLM configuration used, or `None` when no LLM configs were provided.
- `task_results: list[TaskResult]` — results for each evaluated task.
- `skipped_tasks: list[Task[Target]]`: tasks that raised `NotApplicable` (during `configure_target` or, in dynamic mode, from the resolver).

## LLM access and budget tracking

The controller mediates LLM access for the optimizer. This is part of the threat model — it defines what computational resources the attacker has.

- **Configuration**: Pass `llm_config=LLMConfig(...)` to the controller constructor (optional — omit for non-LLM optimizers). The config specifies the model, API credentials, and an optional cost budget (`max_cost` in USD).
- **Per-task budget**: A fresh `LLMClient` is created for each task. Budget resets per task.
- **Non-LLM optimizers**: When `llm_config` is `None`/omitted, the optimizer receives a noop `LLMClient` that raises `BudgetExhaustedError` on any call.
- **Constrained client**: The `LLMClient` locks the model, API base, and API key. The optimizer cannot override them.
- **Cost-based budget enforcement**: Pre-call checks raise `BudgetExhaustedError` when cumulative cost reaches `max_cost`. Cost is computed per call via `litellm.completion_cost()`, which uses the model's pricing to convert token usage to USD.
- **Usage tracking**: Each `RunResult` includes a cumulative `llm_usage` snapshot (calls, cost). Each `TaskResult` includes the total `llm_usage`. This enables budget-vs-performance analysis across runs.
- **Summary output**: The evaluation summary includes call counts and cost.

## Design decisions

- **Concrete class, not ABC**: There is one orchestration logic.
- **Optimizer factory**: A fresh optimizer is created for each (task, scope, llm_config) combination via `optimizer_factory()`. This ensures clean state and allows threat model-specific initialization.
- **Target factory**: A fresh target is created for each task via `target_factory.create()`. Concurrent tasks never share mutable target state. The factory carries the per-target concurrency limit, which the controller enforces via `asyncio.Semaphore`. Cheap targets (a chatbot wrapping an API) should bump this; heavy targets that hold expensive resources can either stay at the default of 1 or pool internally inside their factory.
- **Channel-based**: Controller creates an `EventChannel` per task. Target's `send_event` callback bridges to `channel.send()` with filtering. Optimizer pulls from channel in `run()`.
- **Multi-run loop**: Runs until optimizer signals `RunEndResponse(done=True)` or `max_runs_per_task` safety limit. `max_runs_per_task` is validated >= 1 at construction.
- **Concurrent optimizer**: `optimizer.run(channel)` is launched as an `asyncio.Task`. The optimizer stays alive across all runs for a task — one channel, one optimizer task per task.
- **Ephemeral reset after each run**: `target.reset_ephemeral_state()` is called after each evaluation to reset ephemeral state.
- **Exception-safe teardown**: `optimizer.teardown()` is called per task in a `finally` block. Each task's `target.teardown()` is called in `_iterate_tasks`'s per-task `finally` so target resources are released before the next task's semaphore slot opens, regardless of how the task ended.
- **Exception-safe channel shutdown**: If `target.run()` or `task.evaluate()` raises, the `finally` block in `_run_task` closes the channel and awaits the optimizer task, preventing deadlock.
- **Per-task error containment**: An unexpected exception escaping `optimizer.on_event`, `target.run`, `task.evaluate`, or `target.reset_ephemeral_state` is caught inside the run loop. The task ends with `stop_reason="error"` and any runs already completed before the failure are preserved in `TaskResult.runs`. Errors raised outside the run loop (e.g. `task.configure_target` non-`NotApplicable`, `optimizer.initialize`) are caught at the `_iterate_tasks` level as a backstop and recorded as a synthetic error `TaskResult` with `runs=[]`. `BudgetExhaustedError` is preserved as `stop_reason="budget_exhausted"` wherever it originates inside the optimizer's run loop or `optimizer.initialize` (so an optimizer that exhausts its budget during a warmup call is not misclassified). `NotApplicable` continues to be handled distinctly (`skipped_tasks`). The rest of the threat model — and every later threat model — still runs and is persisted.
- **Post-task target reset**: `target.reset_ephemeral_state()` is called at the end of every task's run loop in the `finally` block, even when the loop ended via an error and the inner-loop reset-after-success was skipped. This means the next task in the threat model always starts against a target that has been told to reset its ephemeral state at least once after the previous task's last run. The call is wrapped so a failing `target.reset_ephemeral_state()` is logged but does not propagate or block the next task. The `optimizer.initialize` early-return paths (budget-exhausted and generic error) do not invoke this post-task reset because the run loop never started; targets whose `configure_target` mutates more than config slots should not rely on `reset_ephemeral_state` running in that case.
- **Unified trajectory**: Events and responses are recorded directly to the trajectory via the `trajectory_recorder` middleware. No separate event log — the trajectory is the single source of truth.
- **CLI-ready**: Constructor takes plain parameters. A future CLI module can parse config, instantiate components, call `asyncio.run(controller.run())`. `ThreatModelResult` provides structured output for programmatic use.
- **LLM access as threat model parameter**: The model and budget are experiment-level settings, not optimizer choices. The controller creates a constrained `LLMClient` per task and the optimizer cannot escape the configured model/credentials. Budget limits are a fairness measure for comparing optimizer strategies.
- **Per-task LLM budget**: Each task gets a fresh `LLMClient` with reset counters. This ensures budget fairness when evaluating across multiple tasks and enables per-task budget analysis.
- **Cumulative usage snapshots**: `RunResult.llm_usage` is cumulative (includes all prior runs) rather than per-run delta. This is more useful for budget-vs-performance curves — each point shows (total_budget_spent, score_at_that_point).

## Persistence (`results_dir`)

When `results_dir` is provided, the controller writes a two-level layout for the threat model when `run()` completes:

```
results_dir/
├── {scope}__{model}.json            ← claim-level summary
└── {scope}__{model}/
    ├── 00001__{goal}.json            ← per-task detail (one per task)
    └── ...
```

Multiple controllers pointed at the same `results_dir` (the multi-threat-model sweep pattern) each write their own pair of files, named by their scope and model.

- **Naming**: `{sorted_tag1.sorted_tag2...}__{sanitized_model}.json`. Tag and model strings are sanitized (any character outside `[A-Za-z0-9_-]` becomes `_`). When the threat model has read-only tags, their sorted names are appended as a `__ro_{read_only}` component (e.g. `prompt__ro_system__gpt-4o.json`) so threat models differing only in access mode don't collide; all-read & write runs keep the plain `{scope}__{model}.json` name. **In dynamic mode (a `ScopeResolver`) the stem is the sanitized `scope_label`** instead of the tag names (claim file `{label}__{model}.json` and subfolder `{label}__{model}/`), since there is no single run-level scope. When `llm_config` is `None`, the model segment is `no-llm`. Per-task files are named `{NNNNN}__{sanitized_truncated_goal}.json` where the index is 1-based and zero-padded to 5 digits.
- **When**: per-task detail files are written **incrementally** — each one lands on disk as soon as its task finishes (success, error, or budget-exhausted). The claim-level summary file is written at the end of `run()` and acts as a completion marker; if a post-mortem sees the subfolder without the matching summary file, the run was interrupted and the detail files are the authoritative record of what completed.
- **Failed tasks are still persisted**: per-task error containment (see Design decisions) means an unexpected exception inside one task does not skip the threat model. The failing task lands in the on-disk file with `stop_reason="error"`, the partial trajectory accumulated before the crash, and the formatted exception under the `error` field (which lives *outside* the trajectory). Sibling tasks still finish and are persisted.
- **Atomicity**: each individual file is written via temp file + `rename`. A disk failure on one task's write is logged and contained — the controller continues running the remaining tasks. The summary file will still point at the would-be path (the missing file at that path is the signal).
- **Claim-level file**: `version` (`SCHEMA_VERSION`, now `2`), `completed_at`, `scope` (read & write tag names) plus `read_only` (visible-but-not-injectable tags; empty for an all-read & write run), a `scope_label` field (`null` in static mode; the run label in dynamic mode, where `scope`/`read_only` arrays are empty), `llm_config` (model + max_cost only), a `summary` block (`n_tasks`, `n_success`, `n_skipped`, `max_primary_score`, `mean_primary_score`, `total_llm_usage`), per-task summary entries each with a relative `file` path pointing at its detail file, and `skipped_tasks`. No trajectories at this level.
- **Per-task detail file**: self-contained, and repeats `version`, `scope`, `read_only`, `llm_config` plus the task's `goal`, `success`, `best_score`, `best_evaluation`, `llm_usage`, `stop_reason`, and the full `runs` list (each with its trajectory, evaluation, and cumulative `llm_usage`). In dynamic mode each detail file records **that task's own** resolved `scope`/`read_only`, so different files in the same run carry different scopes.
- **Aggregates**: `mean_primary_score` excludes `NotApplicable` tasks (they are reported separately as `n_skipped`). When the claim has no evaluable tasks, `mean_primary_score` and `max_primary_score` are `null`.
- **`stop_reason` per task**: one of `"done"` (optimizer signaled `RunEndResponse(done=True)`), `"max_runs"` (hit the safety cap), `"budget_exhausted"` (`BudgetExhaustedError` was raised), or `"error"` (unexpected exception in optimizer/target/evaluator; the task was abandoned).
- **Secrets**: `LLMConfig.api_key` and `api_base` are explicitly excluded from both claim and detail files. Trajectory contents (e.g. `ObservableEvent.content`) are *not* scrubbed — keep credentials out of log/observable payloads.
- **Collisions**: if either the claim-level file or the task subfolder already exists, the writer raises `FileExistsError` rather than overwriting. Pass a per-run subdirectory if you re-run into the same parent.

When `results_dir` is `None` (the default), nothing is written and behavior is unchanged.
