# Target, Task & SecurityClaim

## Target (`interfaces/target.py`)

The AI system under test. Exposes four surfaces:

### Pre-run configuration
- `config_specs -> list[ConfigSpec]` — declares named text-valued config slots with security domains.
- `set_config(name, value)` — accepts a config value before a run.

### Post-run state
- `state_specs -> list[StateSpec]` — declares named queryable state (name + description).
- `get_state(name) -> str` — returns post-run ground truth for evaluation.

Config and state are **intentionally distinct**. What you configure before a run (e.g. seeding a database) is not the same as what you query after (e.g. the model's final response).

### Runtime surfaces
- `get_controllables() -> list[Controllable]` — injection points the optimizer can manipulate during a run.
- `get_observables() -> list[ObservableValue]` — static context about the system.

### Execution
- `run(trajectory, send_event)` — execute one run. Emit entries to trajectory. Call `send_event(event)` at controllable points and use the response.

`EventHandler = Callable[[Event], Awaitable[EventResponse]]` — the `send_event` callback. Can be wired directly to the optimizer or through a controller queue. The target doesn't know or care.

## Task (`interfaces/task.py`)

### Generic over target type

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

### Stateless design

Tasks hold no reference to the target. `configure` returns what it set (framework caches). `evaluate` receives the target for on-demand ground-truth queries.

**Why stateless**: Tasks are iterated from SecurityClaims repeatedly. Statelessness means no cleanup, no stale references, safe re-iteration.

### Methods

- `goal -> Goal` — property, the adversarial objective.
- `configure(target) -> dict[str, str]` — set pre-run config, return what was set. Raise `NotApplicable` if incompatible.
- `evaluate(trajectory, target) -> EvaluationResult` — query post-run state, assess success.

## SecurityClaim (`interfaces/security_claim.py`)

Composable, re-iterable collection of tasks.

### Construction

Two factory methods — never mixed:

```python
# From tasks directly
claim = SecurityClaim.from_tasks([task_a, task_b])

# From other claims (lazy chaining)
combined = SecurityClaim.from_claims([claim_1, claim_2])
```

`__init__` raises `TypeError` — must use factory methods.

### Composition model

Claims-of-claims use lazy chaining (`yield from`). No eager flattening. A package exports claims, consumers compose them:

```python
# Package A exports
rag_confidentiality = SecurityClaim.from_tasks([SecretLeakTask(), DocPoisonTask()])
rag_integrity = SecurityClaim.from_tasks([PromptInjectionTask()])

# Consumer composes
full_rag_suite = SecurityClaim.from_claims([rag_confidentiality, rag_integrity])
```

### Design decisions

- **Factory methods over `__init__`**: No runtime isinstance checks needed. Each factory knows its input type.
- **Homogeneous input**: Either all tasks or all claims. Prevents ambiguity.
- **Lazy chaining**: `from_claims` stores references, iterates on demand. Efficient for deep composition.
- **Re-iterable**: Tasks are stateless, so iterating a claim multiple times is safe.

## ConfigSpec & StateSpec (`types/state.py`)

### ConfigSpec (frozen)
Pre-run configuration slot: `name`, `security_domain: SecurityDomainTag`, `description`.

The description IS the format contract. Example: `"One or more SQL INSERT statements, semicolon-separated"`. The target interprets the text.

### StateSpec (frozen)
Post-run queryable state: `name`, `description`.

No security domain — this is ground-truth data for the evaluator, not an attack surface. Example: `"The model's final response text"`.
