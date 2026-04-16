# Controller

The controller is the main orchestrator for red-teaming evaluations. It iterates **threat models** — combinations of a security domain scope (`Scope`) and an optional LLM configuration — and for each threat model evaluates every task in the security claim.

## Construction

```python
from superred.core.controller import Controller
from superred.core.types.llm import LLMConfig
from superred.core.types.security_domain import Scope

target = MyTarget(api_key="sk-...")  # manual values at construction
claim = SecurityClaim.from_tasks([task_a, task_b])

llm_config = LLMConfig(
    model="gpt-4o-mini",
    api_base="https://api.openai.com",
    api_key="sk-...",
    max_cost=5.00,  # USD budget limit (optional, None = unlimited)
)

controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),  # fresh optimizer per (task, scope, config)
    target=target,
    security_claim=claim,
    llm_configs=[llm_config],       # optional — omit for non-LLM optimizers
    max_runs_per_task=100,          # safety limit, default 100
    include_feedback=True,          # populate RunEndEvent.evaluation (default True)
)

# Run with explicit scopes
scope: Scope = frozenset({external_tag})
result = await controller.run(scopes=[scope])

# Or let the controller derive scopes from target.security_domain.distinct_combinations()
result = await controller.run()
```

The controller does not create an asyncio event loop — the caller provides it via `asyncio.run()` or an existing loop.

## Threat model iteration

`await controller.run(scopes=..., models=...) -> ControllerResult`:

The controller iterates all combinations of (scope, llm_config):
- **scopes**: Defaults to `target.security_domain.distinct_combinations()` (non-empty subsets). Each scope is a `frozenset[SecurityDomainTag]`.
- **llm_configs**: Passed at construction. `models=` filters by model name at run time.
- When `llm_configs` is empty, scopes are iterated without LLM configs (for non-LLM optimizers).
- When both are provided, every scope × config combination is tested.

For each threat model, a fresh optimizer is instantiated via `optimizer_factory()`.

## Run lifecycle

For each (scope, llm_config) combination:

1. **Per task** (from security claim):
   - `task.configure_target(target)` — if `NotApplicable`, skip task.
   - Create `LLMClient` from `llm_config` (fresh per task — budget is per-task). If no `llm_config`, use a noop client.
   - Create fresh optimizer via `optimizer_factory()`.
   - `optimizer.initialize(goal, filtered_controllables, filtered_observables, llm_client)` — only controllables and observables within the security domain scope are passed.
   - Create `EventChannel`, launch `optimizer.run(channel)` as concurrent `asyncio.Task`.
   - **Run loop** (until optimizer signals done or `max_runs_per_task`):
     - Create `Trajectory(filtered_scope=scope)`. Access `trajectory.filtered` for optimizer's view.
     - Send `RunStartEvent(filtered_trajectory)` through channel — optimizer gets filtered view.
     - `target.run(emit, send_event)` — target emits `LogEvent` instances via `emit(event)`; `send_event` bridges to channel with security domain filtering. The `trajectory_recorder` middleware records all events and responses directly to the trajectory.
     - `task.evaluate(trajectory, target)` — returns `EvaluationResult`. Controller filters `sub_scores` by scope (keeping only in-scope scores).
     - Send `RunEndEvent(evaluation=filtered_eval, security_domain=<scope_tag>)` through channel — `RunEndEvent` is persisted to the trajectory. When `include_feedback=True` (default), `evaluation` carries the filtered result; when `False`, `evaluation` is `None`. Check `RunEndResponse.done`.
     - Close the trajectory.
     - `target.cleanup()` — reset target state for next run.
     - Track best score, success across runs.
     - If `done=True`, break.
   - Close channel, await optimizer task, `optimizer.teardown()`.
   - Collect `TaskResult`.
2. **Target teardown** (in `finally` — always runs, even on exception): `target.teardown()`.
3. **Summary**: Print human-readable results to stdout.
4. **Return** `ControllerResult`.

### Internal structure

- `_iterate_threat_models(scopes, llm_configs)` — iterates all (scope, llm_config) combinations.
- `_iterate_tasks(scope, llm_config)` — manages all tasks for one threat model.
- `_run_task(task, scope, llm_config)` — manages the full lifecycle for one task: configure, create fresh optimizer, initialize, build middleware stack, run loop, collect results.
- `_run_single(task, channel, scope, run_number)` — executes one iteration: RunStartEvent → target.run → evaluate → RunEndEvent (with evaluation) → close trajectory. Returns `(trajectory, evaluation, done)`.

The `send_event` callback passed to `target.run` is built by composing middleware onto `channel.send`:
```python
send_event = compose(
    trajectory_recorder(trajectory),
    security_domain_filter(scope),
)(channel.send)
```

Users can add custom middleware (logging, tracing, budget enforcement) by extending the composition.

## Security domain filtering

The controller enforces the security domain scope across **all optimizer inputs**:

1. **Controllables**: Filtered with `scope_includes(scope, c.security_domain)` before `optimizer.initialize()`. Out-of-scope controllables are never exposed to the optimizer.
2. **Observables**: Filtered with `scope_includes(scope, o.observable.security_domain)` before `optimizer.initialize()`. Out-of-scope observables are never exposed to the optimizer.
3. **Events**: `ControllablePreCallEvent` and `ControllablePostCallEvent` for out-of-scope controllables are answered with `ControllableNoInjection` without reaching the optimizer. Implemented as the `security_domain_filter` middleware composed onto `channel.send`.
4. **Trajectory**: The optimizer receives a `FilteredTrajectory` (via `RunStartEvent`) that only exposes items within the security domain scope.
5. **Feedback**: Each `Score` in the `EvaluationResult` carries a `security_domain`. The controller filters `sub_scores` to only include in-scope scores. The `RunEndEvent` carries the filtered evaluation directly (when `include_feedback=True`, the default) and is persisted to the trajectory with `security_domain` set to a tag from the scope. `primary_score`, `success`, and `rationale` are always included (the optimizer needs the main optimization signal). The optimizer reads feedback from `event.evaluation` on `RunEndEvent`, or from past trajectories.

A `Scope` is a `frozenset[SecurityDomainTag]`. `scope_includes(scope, tag)` returns `True` if ANY tag in the scope includes the target tag. This allows testing specific security boundaries — scoping to `{external_tag}` tests only external-facing surfaces, while scoping to `{root_tag}` tests everything.

## Unified trajectory as event log

There is no separate event log. The `trajectory_recorder` middleware records all events and responses directly into the trajectory as `Event | EventResponse` objects:

- **Controllable events** — `ControllablePreCallEvent`, `ControllablePostCallEvent`.
- **Controllable responses** — `ControllableInjection`, `ControllableNoInjection`.
- **Log events** — `LogEvent` emitted by the target (model requests, model responses, etc.).
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

### ThreatModelResult (frozen)

Results for one (scope, llm_config) combination:
- `scope: Scope` — the security domain scope tested.
- `llm_config: LLMConfig | None` — the LLM configuration used, or `None` when no LLM configs were provided.
- `task_results: list[TaskResult]` — results for each evaluated task.
- `skipped_tasks: list[Task[Target]]` — tasks that raised `NotApplicable`.

### ControllerResult (frozen)

The full evaluation:
- `threat_model_results: list[ThreatModelResult]` — results for each threat model evaluated.

## LLM access and budget tracking

The controller mediates LLM access for the optimizer. This is part of the threat model — it defines what computational resources the attacker has.

- **Configuration**: Pass `llm_configs=[LLMConfig(...)]` to the controller constructor (optional — omit for non-LLM optimizers). Each config specifies the model, API credentials, and an optional cost budget (`max_cost` in USD).
- **Per-task budget**: A fresh `LLMClient` is created for each task. Budget resets per task.
- **Non-LLM optimizers**: When `llm_configs` is empty/omitted, the optimizer receives a noop `LLMClient` that raises `BudgetExhaustedError` on any call.
- **Constrained client**: The `LLMClient` locks the model, API base, and API key. The optimizer cannot override them.
- **Cost-based budget enforcement**: Pre-call checks raise `BudgetExhaustedError` when cumulative cost reaches `max_cost`. Cost is computed per call via `litellm.completion_cost()`, which uses the model's pricing to convert token usage to USD.
- **Usage tracking**: Each `RunResult` includes a cumulative `llm_usage` snapshot (calls, cost). Each `TaskResult` includes the total `llm_usage`. This enables budget-vs-performance analysis across runs.
- **Summary output**: The evaluation summary includes call counts and cost.

## Design decisions

- **Concrete class, not ABC**: There is one orchestration logic.
- **Optimizer factory**: A fresh optimizer is created for each (task, scope, llm_config) combination via `optimizer_factory()`. This ensures clean state and allows threat model-specific initialization.
- **Channel-based**: Controller creates an `EventChannel` per task. Target's `send_event` callback bridges to `channel.send()` with filtering. Optimizer pulls from channel in `run()`.
- **Multi-run loop**: Runs until optimizer signals `RunEndResponse(done=True)` or `max_runs_per_task` safety limit. `max_runs_per_task` is validated >= 1 at construction.
- **Concurrent optimizer**: `optimizer.run(channel)` is launched as an `asyncio.Task`. The optimizer stays alive across all runs for a task — one channel, one optimizer task per task.
- **Cleanup after each run**: `target.cleanup()` is called after each evaluation to reset state.
- **Exception-safe teardown**: `optimizer.teardown()` is called per task in a `finally` block. `target.teardown()` is called once in the outer `finally` block.
- **Exception-safe channel shutdown**: If `target.run()` or `task.evaluate()` raises, the `finally` block in `_run_task` closes the channel and awaits the optimizer task, preventing deadlock.
- **Unified trajectory**: Events and responses are recorded directly to the trajectory via the `trajectory_recorder` middleware. No separate event log — the trajectory is the single source of truth.
- **CLI-ready**: Constructor takes plain parameters. A future CLI module can parse config, instantiate components, call `asyncio.run(controller.run())`. `ControllerResult` provides structured output for programmatic use.
- **LLM access as threat model parameter**: The model and budget are experiment-level settings, not optimizer choices. The controller creates a constrained `LLMClient` per task and the optimizer cannot escape the configured model/credentials. Budget limits are a fairness measure for comparing optimizer strategies.
- **Per-task LLM budget**: Each task gets a fresh `LLMClient` with reset counters. This ensures budget fairness when evaluating across multiple tasks and enables per-task budget analysis.
- **Cumulative usage snapshots**: `RunResult.llm_usage` is cumulative (includes all prior runs) rather than per-run delta. This is more useful for budget-vs-performance curves — each point shows (total_budget_spent, score_at_that_point).
