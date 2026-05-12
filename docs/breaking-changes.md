# Breaking Changes

## v0.2.0 (unreleased)

### Controller is now one threat model: `target_factory`, single `scope`, single `llm_config`

The controller was previously a fan-out: it iterated the Cartesian
product of `scopes` × `llm_configs` and returned a `ControllerResult`
wrapping a list of `ThreatModelResult`.  It now models exactly one
threat model — a single `(scope, llm_config)` combination — and
returns a `ThreatModelResult` directly.  Sweeping multiple threat
models is the caller's job.

The same change replaces `target: Target` with `target_factory: TargetFactory`
so each task in the claim gets its own target instance and tasks run
concurrently up to `target_factory.concurrency`.

```python
# Before
controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),
    target=MyTarget(api_key="sk-..."),
    security_claim=claim,
    llm_configs=[cfg_a, cfg_b],          # list, optional
)
result = await controller.run(scopes=[scope_a, scope_b])   # Cartesian product
task_results = result.threat_model_results[0].task_results  # one ThreatModelResult per (scope, cfg)

# After
from superred.core.controller import Controller, TargetFactory

target_factory = TargetFactory(
    create=lambda: MyTarget(api_key="sk-..."),
    concurrency=8,                       # default 1 (sequential, old per-task behavior)
)
controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),
    target_factory=target_factory,
    security_claim=claim,
    scope=scope_a,                       # required, single Scope
    llm_config=cfg_a,                    # optional, single LLMConfig
)
tmr = await controller.run()             # -> ThreatModelResult (not ControllerResult)
task_results = tmr.task_results

# Multiple threat models = multiple controllers at the caller:
import asyncio, itertools
results = await asyncio.gather(*(
    Controller(
        scope=s, llm_config=c,
        optimizer_factory=..., target_factory=target_factory,
        security_claim=claim,
    ).run()
    for s, c in itertools.product([scope_a, scope_b], [cfg_a, cfg_b])
))
```

What changed:

- **`target` → `target_factory`**: each task gets its own `Target` from `target_factory.create()`. Concurrent tasks never share mutable target state.
- **Parallel tasks within a threat model**: bounded by `target_factory.concurrency` via `asyncio.Semaphore` + `asyncio.gather`. Default `concurrency=1` preserves sequential behavior.
- **`target.teardown()` is per-task** and runs in the inner finally before the next task acquires its semaphore slot.
- **`llm_configs: Sequence[LLMConfig]` → `llm_config: LLMConfig | None`**: one config per controller, no list.
- **`scope: Scope`** is now a required constructor arg; `run()` no longer takes `scopes=` or `models=`.
- **`ControllerResult` is removed**; `controller.run()` returns a `ThreatModelResult` directly.
- **No default-scope behavior**: experiments that want `target.security_domain.distinct_combinations()` build it themselves before constructing controllers.
- **Partial trajectory + exception on failure**: when a run raises mid-execution, the trajectory accumulated up to the crash is preserved as the final `RunResult` with a zero-score evaluation, and `TaskResult.error` carries the formatted traceback. Both fields land in the persisted JSON.

Migration:

1. Wrap target construction: `target=MyTarget(...)` → `target_factory=TargetFactory(create=lambda: MyTarget(...))`. For tests, use `TargetFactory.singleton(my_target)` (concurrency=1).
2. Move scope/llm_config into the constructor: drop `run(scopes=[s])`, add `scope=s` and `llm_config=cfg` to `Controller(...)`.
3. Replace `result.threat_model_results[0]` with the direct return.
4. For sweeps, build one Controller per (scope, llm_config) combination and gather them at the experiment level.
5. For real targets that can serve parallel requests (chatbots wrapping API calls), bump `concurrency=` to match the deployed rate limit.

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

### Controller takes optimizer_factory instead of optimizer

A fresh `Optimizer` is now built per task via `optimizer_factory`,
which replaces the old `optimizer: Optimizer` constructor arg.  Combined
with the threat-model collapse above, the migration is:

```python
# Before
controller = Controller(
    optimizer=my_optimizer,
    target=target,
    security_claim=claim,
    security_domain_tag=external_tag,
    llm_config=llm_config,
)

# After (see also the target_factory / scope / llm_config section above)
controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),
    target_factory=TargetFactory(create=lambda: MyTarget(...)),
    security_claim=claim,
    scope=frozenset({external_tag}),
    llm_config=llm_config,
)
```

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
