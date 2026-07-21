---
layout: doc
title: "Task"
permalink: /reference/task
---

# Task

A **task** is one adversarial objective against a target: it sets the target up
before a run, then judges the outcome after. A task holds the "what to test" and
the "did it work"; the [Optimizer](/reference/optimizer) supplies the "how to
attack." Tasks are grouped into a [SecurityClaim](/reference/security-claim), and
the [Controller](/reference/controller) runs one target-and-optimizer pair per
task.

Tasks are **stateless** and **generic over the target type**.

## Generic over the target type

`Task[T_Target]`, where `T_Target` is bound to `Target`. This lets a task bind to
either a specific target class or to the base `Target`.

**Target-specific**, for type-safe access to a concrete target's API:

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
        return EvaluationResult(success=(secret in response), primary_score=Score(...))
```

**Generic**, discovering the target's capabilities at runtime:

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

The `TypeVar` (`T_Target = TypeVar("T_Target", bound=Target)`) ensures the **same**
concrete target type flows through both `configure_target` and `evaluate`.

## Stateless design

A task holds no reference to the target. It receives the target in
`configure_target`, and again in `evaluate`, and stores nothing between them. This
is what lets a claim be **iterated many times** safely: no cleanup, no stale
references. A task should hold only immutable per-objective configuration and read
its result from the target's post-run state.

## Methods

- `goal -> Goal` (property) the adversarial objective. See
  [Goal](/reference/types#goal-goalpy).
- `async configure_target(target) -> None` set pre-run config via
  `target.set_config()`. Returns nothing; configuration is a side effect on the
  target. Raise `NotApplicable` if this task cannot work with this target.
- `async evaluate(trajectory, target) -> EvaluationResult` judge the run. It
  receives the **full, unfiltered** trajectory and the target, and queries post-run
  ground truth via `target.query()`. It returns an
  [`EvaluationResult`](/reference/types#evaluationresult-frozen).

**`NotApplicable`.** A task raises this from `configure_target` to signal it is
incompatible with the given target (not a bug). The exception is named without an
`Error` suffix on purpose. The Controller catches it and collects the task into
[`skipped_tasks`](/reference/results#threatmodelresult), rather than failing.

## Scores, feedback, and the primary score

The evaluation carries a `success: bool`, a `primary_score: Score` (the
optimization signal), optional named `sub_scores`, and a `rationale`. Two rules the
framework enforces or applies:

- **The primary score must be unscoped.** `EvaluationResult.__post_init__` raises
  `ValueError` if `primary_score` carries a `security_domain`. The primary score is
  the signal always delivered to the optimizer; attach domains to `sub_scores`
  instead.
- **Sub-scores are scope-filtered.** Each `sub_score` carries a
  `security_domain` (`SecurityDomainTag | None`). Before the feedback reaches the
  optimizer, the Controller drops sub-scores whose domain is out of scope; an
  untagged one (`None`) stays. The `primary_score`, `success`, and `rationale` are
  always delivered. See [Security Domains](/reference/security-domains#the-five-filtered-surfaces).

Any judges or scorers a task runs during `evaluate` use their own LLM client and do
**not** count against the optimizer's budget, exactly like the target's own
inference.

## Design decisions

- **Generics via `TypeVar`.** The same concrete target type flows through both
  methods, so a target-specific task gets type-checked access to its target's API.
- **`configure_target` returns `None`.** Configuration is a side effect on the
  target, which holds its own state; there is nothing to return.
- **`evaluate` receives the target for queries.** Post-run ground truth may differ
  from the initial config, so the evaluator queries it fresh via `target.query()`
  rather than trusting what was set.
- **`NotApplicable` is a skip, not an error.** It signals incompatibility, and the
  Controller routes it to `skipped_tasks`, keeping the rest of the run going.
