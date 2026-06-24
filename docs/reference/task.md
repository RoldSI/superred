---
layout: doc
title: "Task Interface"
permalink: /reference/task
---

# Task Interface

A task defines an adversarial objective against a target. Tasks are stateless and generic over the target type.

## Generic over target type

`Task[T_Target]` where `T_Target` is bound to `Target`. Two patterns:

**Target-specific**, type-safe access to concrete target API:
```python
class RAGSecretTask(Task[MyRAGTarget]):
    @property
    def goal(self) -> Goal:
        return Goal(description="Extract the secret from the RAG database")

    async def configure_target(self, target: MyRAGTarget) -> None:
        secret = generate_secret()
        target.set_config("db_seed", f"INSERT INTO docs VALUES ('{secret}')")

    async def evaluate(self, trajectory, target) -> EvaluationResult:
        response = target.query("last_response")
        success = secret in response
        return EvaluationResult(...)
```

**Generic**, discovers capabilities at runtime:
```python
class GenericSecretTask(Task[Target]):
    async def configure_target(self, target: Target) -> None:
        spec = next(s for s in target.config_specs if "secret" in s.description.lower())
        target.set_config(spec.name, generate_secret())

    async def evaluate(self, trajectory, target) -> EvaluationResult:
        for spec in target.query_specs:
            value = target.query(spec.name)
            ...
        return EvaluationResult(...)
```

## Stateless design

Tasks hold no reference to the target. `configure_target` sets config and returns nothing. `evaluate` receives the target for on-demand ground-truth queries.

**Why stateless**: Tasks are iterated from SecurityClaims repeatedly. Statelessness means no cleanup, no stale references, safe re-iteration.

## Methods

- `goal -> Goal`, property, the adversarial objective.
- `configure_target(target) -> None`, set pre-run config via `target.set_config()`. Raise `NotApplicable` if incompatible with this target.
- `evaluate(trajectory, target) -> EvaluationResult`, query post-run ground truth via `target.query()`, assess success. Each `sub_score` carries a `security_domain` (`SecurityDomainTag | None`); the controller filters `sub_scores` by scope, dropping only those with an out-of-scope domain (`None` means always visible). The `primary_score` carries no `security_domain` and is never filtered.

## Design decisions

- **Generics via TypeVar**: `T_Target = TypeVar("T_Target", bound=Target)` ensures the same concrete target type flows through both `configure_target` and `evaluate`.
- **`configure_target` returns None**: Configuration is a side effect on the target. No need to return what was set, the target holds its own state.
- **`evaluate` receives target for queries**: The evaluator discovers available queries via `target.query_specs` and calls `target.query(name, **params)`. Post-run state may differ from initial config. Each `sub_score` carries a `security_domain` (`SecurityDomainTag | None`); `None` means always visible. The controller filters `sub_scores` by the active scope before writing feedback to the trajectory, dropping only out-of-scope ones; the `primary_score` carries no `security_domain` and is never filtered.
- **`NotApplicable` exception**: A task that cannot work with a given target raises this from `configure_target`. Named without `Error` suffix (suppressed via `noqa: N818`) because it signals incompatibility, not a bug. The controller catches this and skips the task.
