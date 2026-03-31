# Task Interface

A task defines an adversarial objective against a target. Tasks are stateless and generic over the target type.

## Generic over target type

`Task[T_Target]` where `T_Target` is bound to `Target`. Two patterns:

**Target-specific** — type-safe access to concrete target API:
```python
class RAGSecretTask(Task[MyRAGTarget]):
    async def configure(self, target: MyRAGTarget) -> dict[str, str]:
        target.set_config("db_seed", "INSERT INTO docs VALUES ('secret: abc123')")
        return {"db_seed": "INSERT INTO docs VALUES ('secret: abc123')"}

    async def evaluate(self, trajectory, target) -> EvaluationResult:
        response = target.get_state("last_response")
        ...
```

**Generic** — discovers capabilities at runtime:
```python
class GenericSecretTask(Task[Target]):
    async def configure(self, target: Target) -> dict[str, str]:
        spec = next(s for s in target.config_specs if "secret" in s.description.lower())
        target.set_config(spec.name, "my_secret")
        return {spec.name: "my_secret"}
```

## Stateless design

Tasks hold no reference to the target. `configure` returns what it set (framework caches). `evaluate` receives the target for on-demand ground-truth queries.

**Why stateless**: Tasks are iterated from SecurityClaims repeatedly. Statelessness means no cleanup, no stale references, safe re-iteration.

## Methods

- `goal -> Goal` — property, the adversarial objective.
- `configure(target) -> dict[str, str]` — set pre-run config, return what was set. Raise `NotApplicable` if incompatible.
- `evaluate(trajectory, target) -> EvaluationResult` — query post-run state, assess success.

## Design decisions

- **Generics via TypeVar**: `T_Target = TypeVar("T_Target", bound=Target)` ensures the same concrete target type flows through both `configure` and `evaluate`. A `Task[MyRAGTarget]` gets `MyRAGTarget` in both methods.
- **`configure` returns what it set**: The framework caches this dict. Separates the act of configuring from the record of what was configured.
- **`evaluate` receives target, not cached state**: The evaluator queries post-run ground truth on demand via `target.get_state()`. Post-run state may differ from initial config.
- **`NotApplicable` exception**: A task that cannot work with a given target raises this from `configure`. Named without `Error` suffix (suppressed via `noqa: N818`) because it signals incompatibility, not a bug.
