---
layout: doc
title: "Controller"
permalink: /reference/controller
---

# Controller

The **Controller** is the orchestrator. It runs one
[`SecurityClaim`](/reference/security-claim) against one **threat model**, drives
the [event loop](/reference/events-and-trajectory) between a fresh target and a
fresh optimizer for each task, enforces the security scope, and returns one
[`ThreatModelResult`](/reference/results#threatmodelresult).

A **threat model** is one `(scope, llm_config)` combination, both fixed at
construction. One Controller measures exactly that one combination. Comparing
several is the [caller's job](#sweeping-multiple-threat-models).

This page covers how the Controller is built and how it runs. What a run
**produces**, the result objects, the on-disk tree, resume, and reporting, is on
[Results & Persistence](/reference/results).

## Construction

```python
from superred.core import Controller, TargetFactory, LLMConfig, Scope

# A factory produces fresh target instances and declares how many tasks may
# run in parallel against independent instances.
target_factory = TargetFactory(
    create=lambda: MyTarget(api_key="sk-..."),  # manual values at construction
    concurrency=8,                              # default is 1 (sequential)
)
claim = SecurityClaim.from_tasks([task_a, task_b])

controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),  # fresh optimizer per task
    target_factory=target_factory,            # fresh target per task
    security_claim=claim,
    scope=frozenset({external_tag}),          # read & write surface (visible + injectable)
    read_only=frozenset(),                    # optional: visible-but-not-injectable tags
    llm_config=LLMConfig(                      # optional; omit for a non-LLM optimizer
        model="gpt-4o-mini",
        api_base="https://api.openai.com",
        api_key="sk-...",
    ),
    task_cost_cap_usd=5.00,                    # per-task attacker budget (USD); None = unlimited
    max_runs_per_task=100,                     # safety cap; None resolves to 100
    include_feedback=True,                     # populate RunEndEvent.evaluation (default True)
    # --- output (see Results & Persistence) ---
    persist=True,                              # write a results tree (default True)
    results_dir=None,                          # results ROOT; None = env or ./superred-results/
    overwrite=False,                           # re-run a resumable experiment from scratch
    report="auto",                             # live dashboard on a TTY, plain otherwise; False = silent
    reporter=None,                             # inject a custom ProgressReporter (wins over report)
    attacker_label="my-optimizer",             # short names for the experiment folder + dashboard
    target_label="my-target",
    claim_label="my-claim",
)

tmr = await controller.run()   # -> ThreatModelResult
```

The full constructor parameters, with types and defaults:

| Parameter | Type | Default | Meaning |
|-----------|------|---------|---------|
| `optimizer_factory` | `Callable[[], Optimizer]` | required | builds a fresh optimizer per task |
| `target_factory` | `TargetFactory` | required | builds fresh targets; carries `concurrency` |
| `security_claim` | `SecurityClaim` | required | the tasks to run |
| `scope` | `Scope \| ScopeResolver` | required | read & write surface (or a per-task resolver) |
| `read_only` | `Scope \| ScopeResolver` | `frozenset()` | visible-but-not-injectable surface |
| `llm_config` | `LLMConfig \| None` | `None` | the attacker's model; `None` = non-LLM |
| `task_cost_cap_usd` | `float \| None` | `None` | per-task attacker cost cap; `None` = unlimited |
| `max_runs_per_task` | `int \| None` | `None` (→ 100) | per-task run cap; validated `>= 1` |
| `include_feedback` | `bool` | `True` | whether `RunEndEvent` carries the evaluation |
| `results_dir` | `str \| Path \| None` | `None` | results **root** (see [persistence](/reference/results#persistence)) |
| `scope_label` | `str \| None` | `None` | names a dynamic-scope run; required in that mode |
| `persist` | `bool` | `True` | write a results tree |
| `overwrite` | `bool` | `False` | force a full recompute of a resumable run |
| `reporter` | `ProgressReporter \| None` | `None` | custom progress observer; wins over `report` |
| `report` | `bool \| Literal["auto"]` | `"auto"` | live progress; `False` = silent |
| `attacker_label` / `target_label` / `claim_label` | `str \| None` | `None` | short display names |

The Controller does not create an event loop; the caller provides one via
`asyncio.run(controller.run())` or an existing loop.

### `TargetFactory`

A frozen dataclass bundling "how to make a target" with "how many can run at
once":

- `create: Callable[[], Target]` returns a fresh target instance.
- `concurrency: int = 1` how many tasks may run in parallel against independent
  instances (validated `>= 1`).

Target authors choose `concurrency` by the target's real limits: a chatbot
wrapping an API call can comfortably use 8 or more; a heavy sandboxed target
usually stays at 1 unless it pools internally. For a single shared instance
(tests, an expensive resource), use the classmethod `TargetFactory.singleton(target)`,
which locks `concurrency=1` because a shared instance cannot safely serve
parallel tasks. The Controller still calls `target.teardown()` once per task, so
a multi-task singleton needs an idempotent teardown.

## Scope may be a fixed `Scope` or a per-task `ScopeResolver`

`scope` accepts either a fixed [`Scope`](/reference/security-domains#scope-and-scope_includes)
(one read & write surface applied to every task) **or** a
[`ScopeResolver`](/reference/security-domains#per-task-scopes-scoperesolver) (a
`Callable[[Task], Scope]` that computes the scope **once per task**).
`read_only` independently accepts the same two forms, resolved separately.
`callable(scope)` is the discriminator.

```python
from superred.core import ScopeResolver
from my_target import DB_ORDERS_TAG, DB_CUSTOMERS_TAG

def resolve(task) -> frozenset:
    if task.goal.description.startswith("orders:"):
        return frozenset({DB_ORDERS_TAG})
    return frozenset({DB_CUSTOMERS_TAG})

controller = Controller(
    optimizer_factory=..., target_factory=target_factory, security_claim=claim,
    scope=resolve,            # a resolver, not a frozenset
    scope_label="per-goal",   # REQUIRED whenever scope or read_only is a resolver
)
```

The rules (`scope_label` requirement, task-skip on empty visibility, per-task
error containment, identity matching) are specified in
[Security Domains](/reference/security-domains#per-task-scopes-scoperesolver).
The resolved scope gates **all** optimizer-facing surfaces for that task (see
[Security domain filtering](#security-domain-filtering)).

## The run lifecycle

`await controller.run(*, reporter=None) -> ThreatModelResult` runs every task in
the claim against the configured threat model. (The keyword-only `reporter`
overrides the constructor's for this call; `run_all` uses it to inject a shared
dashboard lane.) Tasks run concurrently, bounded by `target_factory.concurrency`
(an `asyncio.Semaphore` plus `asyncio.gather`), and results are collected in claim
order.

For each task:

1. `target = target_factory.create()` a fresh target owned by this task.
2. `task.configure_target(target)`. If it raises `NotApplicable`, the task is
   collected into `skipped_tasks` and not retried.
3. Build the `LLMClient` from `llm_config` (fresh per task, so the budget is
   per-task). With no `llm_config`, a noop client is used.
4. `optimizer = optimizer_factory()` a fresh optimizer.
5. `optimizer.initialize(goal, filtered_controllables, filtered_observables,
   llm_client)`, only in-scope controllables and observables are passed.
6. Create an `EventChannel` and launch `optimizer.run(channel)` as a concurrent
   task.
7. **Run loop**, until the optimizer signals done or `max_runs_per_task`:
   - Create a `Trajectory(filtered_scope=scope)`; its `.filtered` view is the
     optimizer's.
   - Send `RunStartEvent` (carrying the filtered trajectory).
   - `target.run(emit, send_event)`. The target emits observable events and pauses
     at controllable points; the composed middleware filters and records (see
     [below](#security-domain-filtering)).
   - `task.evaluate(trajectory, target)` produces an `EvaluationResult`; the
     Controller filters its `sub_scores` by scope.
   - Send `RunEndEvent(evaluation=...)` (persisted to the trajectory). With
     `include_feedback=True`, the filtered evaluation is attached.
   - Close the trajectory; call `target.reset_ephemeral_state()` for the next run.
   - Track best score and success across runs.
8. Close the channel, await the optimizer task, `optimizer.teardown()`. A final
   `target.reset_ephemeral_state()` then `target.teardown()`, and the instance is
   discarded.

A **run** is one full pass of the target plus its evaluation. A task may take many
runs; the loop ends when the optimizer returns `RunEndResponse(done=True)`, a
`BudgetExhaustedError` is raised, or `max_runs_per_task` is reached. The
`stop_reason` on each [`TaskResult`](/reference/results#taskresult) records which.

Throughout, the Controller streams live progress to a
[reporter](/reference/results#live-progress-reporting) and, unless `persist=False`,
[persists](/reference/results#persistence) each task the moment it finishes.

## Security domain filtering

Enforcing the threat model is the Controller's core job. It filters the scope
across **every** optimizer-facing surface. It derives two scopes from its `scope`
and `read_only` arguments: the **write scope** (= `scope`) and the **visibility
scope** (= `scope | read_only`); when `read_only` is empty they are identical.

1. **Controllables.** Only the **injectable** ones (matched against the write
   scope) are passed to `initialize()`. The list means exactly "what the optimizer
   can inject into."
2. **Observables.** In-scope observables (visibility scope), **plus** each
   read-only controllable re-presented as an `ObservableValue` (with
   `content=None`). So `observables` means "what the optimizer can read."
3. **Controllable events.** Events for controllables outside the write scope are
   answered with `ControllableNoInjection` without reaching the optimizer. This is
   the [`security_domain_filter` middleware](/reference/events-and-trajectory#middleware-where-scope-and-recording-live)
   composed onto `channel.send`. Because it is given the **write** scope, events
   under `read_only` tags are also declined, but, being within the visibility
   scope, they and their responses stay recorded and visible.
4. **Trajectory.** The optimizer receives a
   [`FilteredTrajectory`](/reference/events-and-trajectory#trajectory) of only
   in-scope items (visibility scope).
5. **Feedback.** `sub_scores` whose `security_domain` is out of scope are dropped
   (an untagged sub-score is always visible). The `primary_score`, `success`, and
   `rationale` are always delivered.

The full model, tags, forest, `scope` versus `read_only`, and resolvers, is on
[Security Domains](/reference/security-domains). The filtering itself is
implemented as [middleware](/reference/events-and-trajectory#middleware-where-scope-and-recording-live)
composed onto the channel:

```python
send_event = compose(
    trajectory_recorder(trajectory),          # records every event and response
    security_domain_filter(write_scope),      # declines non-injectable controllables
)(channel.send)
```

## LLM access and budget

The Controller mediates the optimizer's LLM access; this is part of the threat
model (it defines the attacker's compute).

- **Configuration.** `llm_config=LLMConfig(...)` sets the model and credentials
  (optional; omit for a non-LLM optimizer, which then gets a noop client).
- **Per-task budget.** `task_cost_cap_usd` (USD) caps the attacker's cost. A fresh
  [`LLMClient`](/reference/types#llmclient-corellmpy) is built per task, so the cap
  resets per task (`None` = unlimited). It bounds only the attacker; the judge and
  target are never bounded by it.
- **Constrained client.** The `LLMClient` locks the model and credentials; the
  optimizer cannot override them. Cost is computed per call via
  `litellm.completion_cost()`, and a pre-call check raises `BudgetExhaustedError`
  once the cap is reached.
- **Usage tracking.** Each result carries usage (see
  [`RunResult`](/reference/results#runresult) / [`TaskResult`](/reference/results#taskresult)),
  enabling per-run cost and budget-versus-performance analysis.

## Sweeping multiple threat models

One Controller is one threat model. A sweep is several Controllers, built by the
caller. To share **one** live dashboard across them, use `run_all`:

{% include diagrams/d6.html %}

```python
import itertools
from superred.core import Controller
from superred.core.controller import run_all

controllers = [
    Controller(
        scope=s, llm_config=c,
        optimizer_factory=..., target_factory=target_factory, security_claim=claim,
    )
    for s, c in itertools.product(scopes, configs)
]
results = await run_all(controllers, concurrency=4)   # <= 4 threat models at once
```

`run_all(controllers, *, concurrency=None, report="auto")` runs the Controllers
(all at once when `concurrency` is `None`), coordinates them onto a single shared
dashboard, and returns their `ThreatModelResult`s in input order. A bare
`asyncio.gather(*(c.run() for c in controllers))` also runs and persists
correctly, but does not coordinate the live display. If they share one
`results_dir` root, the `experiments.json` index links them all (see
[persistence](/reference/results#persistence)).

## Design decisions

- **A concrete class, not an ABC.** There is one orchestration logic.
- **Fresh instances per task.** A new optimizer (`optimizer_factory()`) and a new
  target (`target_factory.create()`) per task, so concurrent tasks never share
  mutable state and each starts clean.
- **Channel-based bridging.** The Controller creates one `EventChannel` per task
  and bridges the target's `send_event` onto it through the middleware stack; the
  optimizer pulls from the channel at its own pace.
- **The optimizer outlives the runs.** `optimizer.run(channel)` is one task that
  stays alive across every run of the task; only the target is reset between runs.
- **Ephemeral reset between runs; fresh instance between tasks.**
  `target.reset_ephemeral_state()` runs after each evaluation and once more at task
  end (in a `finally`, so it runs even after an error). Durable state survives it;
  it is discarded only when the next task gets a fresh instance.
- **Per-task error containment.** An unexpected exception escaping the optimizer,
  target, or evaluator is caught inside the run loop: the task ends with
  `stop_reason="error"`, its partial trajectory and traceback are preserved, and
  the rest of the run, and every later threat model, still runs and is persisted.
  `BudgetExhaustedError` is preserved distinctly as `"budget_exhausted"`, and
  `NotApplicable` as a skip.
- **Exception-safe shutdown.** If a run raises, the `finally` closes the channel
  and awaits the optimizer task, so no `channel.send` deadlocks; teardown of both
  optimizer and target is wrapped in `finally`.
- **The trajectory is the single event log.** Events and responses are recorded
  directly onto the trajectory, the
  [`trajectory_recorder`](/reference/events-and-trajectory#middleware-where-scope-and-recording-live)
  for the controllable traffic, the target's `emit` for observable events, and the
  controller itself for the `RunEndEvent`. There is no separate log.
