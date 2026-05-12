# Breaking Changes

## v0.2.0 (unreleased)

### Controller now takes target_factory; tasks run in parallel per threat model

`Controller` no longer accepts a single `target: Target` instance. Pass a
`TargetFactory` instead — it produces a fresh `Target` per task and
declares how many tasks the controller may run in parallel within a
threat model.

```python
# Before
controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),
    target=MyTarget(api_key="sk-..."),
    security_claim=claim,
    llm_configs=[cfg],
)

# After
from superred.core.controller import Controller, TargetFactory

target_factory = TargetFactory(
    create=lambda: MyTarget(api_key="sk-..."),
    concurrency=8,  # default is 1 (sequential, old behavior)
)
controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),
    target_factory=target_factory,
    security_claim=claim,
    llm_configs=[cfg],
)
```

What changed:

- **Per-task target lifecycle**: each task gets its own `Target` instance from `target_factory.create()`. Concurrent tasks never share mutable target state. There is no controller-level long-lived target.
- **Parallel task execution**: within one threat model, tasks run concurrently bounded by `target_factory.concurrency` via `asyncio.Semaphore` + `asyncio.gather`. Results are returned in input order. Default `concurrency=1` preserves sequential behavior.
- **`target.teardown()` is per-task**, called in `_iterate_tasks`'s per-task `finally` before the semaphore slot is released. The outer controller-level teardown is gone.
- **Probe target for default scopes**: when `run()` is called without explicit `scopes=`, the controller builds one short-lived target via the factory, reads `security_domain.distinct_combinations()`, and tears it down immediately.

Migration:

1. Wrap target construction in a factory: `target=MyTarget(...)` → `target_factory=TargetFactory(create=lambda: MyTarget(...))`.
2. For single-instance migration (tests, expensive-to-construct resources), use `target_factory=TargetFactory.singleton(my_target)` — concurrency is locked to 1.
3. For real targets that can serve parallel requests (chatbots wrapping API calls, etc.), bump `concurrency=` on the factory to match the deployed rate limit.

### Optimizer.initialize() signature change

The `llm_client` parameter on `Optimizer.initialize()` is now required (`LLMClient`, not `LLMClient | None`). The base class stores the client — subclasses must call `super().initialize(...)` for `self.llm` to work.

```python
# Before
async def initialize(
    self,
    goal: Goal,
    controllables: list[Controllable],
    observables: list[ObservableValue],
    llm_client: LLMClient | None = None,
) -> None: ...

# After
async def initialize(
    self,
    goal: Goal,
    controllables: list[Controllable],
    observables: list[ObservableValue],
    llm_client: LLMClient,
) -> None: ...
```

**Impact**: All existing `Optimizer` subclasses must update their `initialize()` signature to accept `llm_client: LLMClient` (required, not optional) and call `super().initialize(...)`.

**Migration**: Change `llm_client: LLMClient | None = None` to `llm_client: LLMClient` and add a `super()` call.

```python
class MyOptimizer(Optimizer):
    async def initialize(
        self, goal, controllables, observables, llm_client,
    ) -> None:
        await super().initialize(goal, controllables, observables, llm_client)
        # self.llm is now available
        ...
```

### Controller llm_config is now required

The `llm_config` parameter on `Controller` is now required (no longer optional). LLM access is part of the threat model and must always be specified.

**Migration**: Pass `llm_config=LLMConfig(...)` to the `Controller` constructor.

### LLMUsage is no longer optional on result types

`RunResult.llm_usage` and `TaskResult.llm_usage` are now `LLMUsage` (not `LLMUsage | None`). They are always present since `llm_config` is required.

**Migration**: Remove `is not None` checks around `llm_usage` access.

### New core dependency: litellm

The `superred` package now depends on `litellm>=1.0`. This is pulled in automatically via pip. No action needed unless you pin dependencies — add `litellm` to your pins.

### Cost-based budget enforcement

`LLMConfig` now uses `max_cost: float | None` (USD) instead of the previous `max_calls`/`max_input_tokens`/`max_output_tokens` fields. `LLMUsage` now tracks `calls: int` and `cost: float` only (token fields removed). Budget enforcement is based on USD cost computed via `litellm.completion_cost()`.

**Migration**: Replace `max_calls=N` / `max_input_tokens=N` / `max_output_tokens=N` with `max_cost=X.XX` (USD amount). Remove any references to `input_tokens` or `output_tokens` on `LLMUsage`.

### Controller now takes optimizer_factory and iterates threat models

The `Controller` constructor signature has changed significantly:

```python
# Before
controller = Controller(
    optimizer=my_optimizer,
    target=target,
    security_claim=claim,
    security_domain_tag=external_tag,
    llm_config=llm_config,
)
result = await controller.run()
task_results = result.task_results

# After
controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),   # factory, not instance
    target=target,
    security_claim=claim,
    llm_configs=[llm_config],                  # list, optional
)
result = await controller.run(scopes=[frozenset({external_tag})])
task_results = result.threat_model_results[0].task_results
```

Key changes:
- **`optimizer` → `optimizer_factory`**: A callable that returns a fresh `Optimizer`. A new optimizer is created for each (task, scope, llm_config) combination.
- **`security_domain_tag` removed**: Scopes are passed to `run(scopes=...)`. Each scope is a `frozenset[SecurityDomainTag]` (the `Scope` type alias). Default scopes come from `target.security_domain.distinct_combinations()`.
- **`llm_config` → `llm_configs`**: Now an optional list. Omit for non-LLM optimizers. Each config is tested with each scope (Cartesian product).
- **`ControllerResult.task_results` → `ControllerResult.threat_model_results`**: Results are nested under `ThreatModelResult`, one per (scope, llm_config) combination. Each `ThreatModelResult` has `task_results` and `skipped_tasks`.
- **`run()` accepts `scopes` and `models` arguments**: `scopes` is a list of `Scope` values. `models` filters `llm_configs` by model name.

**Migration**:
1. Wrap optimizer construction in a lambda/function: `optimizer=X` → `optimizer_factory=lambda: X`
2. Change `llm_config=cfg` to `llm_configs=[cfg]` (or omit for non-LLM)
3. Move scope to run: `security_domain_tag=tag` → `run(scopes=[frozenset({tag})])`
4. Access results via `result.threat_model_results[0].task_results` instead of `result.task_results`

### New types: Scope, scope_includes, ThreatModelResult, OptimizerFactory

- `Scope = frozenset[SecurityDomainTag]` — type alias for multi-tag attack surface scope.
- `scope_includes(scope, tag)` — returns `True` if any tag in the scope includes the target tag.
- `ThreatModelResult` — frozen dataclass grouping results for one (scope, llm_config) combination.
- `OptimizerFactory = Callable[[], Optimizer]` — type alias for optimizer factories.

All are exported from `superred.core` and `superred.core.types`.

### Feedback scoping: RunEndEvent change, evaluation order, include_feedback

Three interrelated changes to how feedback flows to the optimizer:

**1. RunEndEvent carries evaluation, not trajectory**

`RunEndEvent.trajectory` has been replaced with `RunEndEvent.evaluation: EvaluationResult | None` (default `None`). The optimizer no longer receives the trajectory through RunEndEvent — use `self.current_trajectory` instead (available via `_dispatch`).

```python
# Before
if isinstance(event, RunEndEvent):
    for entry in event.trajectory.snapshot():
        ...

# After
if isinstance(event, RunEndEvent):
    # Read evaluation directly from the event:
    if event.evaluation is not None:
        score = event.evaluation.primary_score.value
    # Or from the trajectory:
    if self.current_trajectory is not None:
        for entry in self.current_trajectory.snapshot():
            ...
```

**2. RunEndEvent is now persisted to the trajectory**

`RunEndEvent` is persisted to the trajectory (previously it was not). Its `security_domain` is set from the active scope (required for trajectory validation). Evaluation happens *before* `RunEndEvent` is sent. The order is: `target.run()` → `evaluate()` → `RunEndEvent` (with evaluation) → `trajectory.close()`.

**3. Controller `include_feedback` flag**

`Controller.__init__` accepts `include_feedback: bool = True`. When `True`, `RunEndEvent.evaluation` carries the filtered `EvaluationResult`; when `False`, `evaluation` is `None`. The optimizer reads feedback from `event.evaluation` on `RunEndEvent`, or from past trajectories (since `RunEndEvent` is persisted).

**Impact**: Optimizers that accessed `RunEndEvent.trajectory` must switch to `self.current_trajectory` or `event.evaluation`. `FeedbackEvent` has been removed entirely — remove any imports or `isinstance` checks for it. Read feedback from `event.evaluation` on `RunEndEvent` or from the trajectory instead.

**Migration**:
1. Replace `event.trajectory` on `RunEndEvent` with `self.current_trajectory` or `event.evaluation`.
2. Remove all `FeedbackEvent` imports and handlers — the type no longer exists.
3. To read feedback, use `event.evaluation` on `RunEndEvent` or query past trajectories.
