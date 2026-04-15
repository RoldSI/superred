# Breaking Changes

## v0.2.0 (unreleased)

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
