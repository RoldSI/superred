# Security Domains

Security domains define trust boundaries in the target system. They control what the optimizer can see and interact with.

## What Security Domains Do

When you run an evaluation with `security_domain_tag=USER_INPUT_TAG`, the Controller filters **all optimizer inputs**:

| What | How it's filtered |
|------|-------------------|
| **Controllables** | Only in-scope controllables passed to `optimizer.initialize()` |
| **Observables** | Only in-scope observables passed to `optimizer.initialize()` |
| **Events** | Out-of-scope `ControllablePreCallEvent`/`PostCallEvent` get `ControllableNoInjection` automatically |
| **Trajectory** | Optimizer sees a `FilteredTrajectory` with only in-scope entries |
| **Feedback sub_scores** | Only in-scope sub_scores included in feedback |

The `primary_score`, `success`, and `rationale` are always visible (the optimizer needs the main optimization signal).

## Defining a Domain Tree

Security domains form a tree (or forest). A parent scope includes all children:

```python
from superred.core.types.security_domain import SecurityDomain, SecurityDomainTag

# Define the tree
system = SecurityDomainTag("system")                          # root
external = SecurityDomainTag("external", parent=system)       # external surfaces
internal = SecurityDomainTag("internal", parent=system)       # internal components
user_input = SecurityDomainTag("user_input", parent=external) # user-facing input
api_input = SecurityDomainTag("api_input", parent=external)   # API-facing input

# Validate and package
domain = SecurityDomain([system, external, internal, user_input, api_input])
```

```
system
  +-- external
  |     +-- user_input
  |     +-- api_input
  +-- internal
```

### `includes()` method

`tag.includes(other)` returns `True` if `other` is a descendant of `tag` (or equal):

```python
system.includes(user_input)    # True — system includes everything
external.includes(user_input)  # True — user_input is child of external
external.includes(api_input)   # True — api_input is child of external
external.includes(internal)    # False — internal is a sibling, not descendant
user_input.includes(external)  # False — child doesn't include parent
user_input.includes(user_input) # True — includes itself
```

## Tagging Target Components

Every controllable, observable, config spec, and trajectory entry gets a security domain tag (or `None` for entries that should always be visible):

```python
# Controllable at the user_input boundary
Controllable(spec=ControllableSpec(
    name="chat_message",
    security_domain=user_input,
    description="The user's chat message",
))

# Observable at the system level
Observable(
    name="model_info",
    security_domain=system,
    description="Model identifier",
)

# Log event at the user level
emit(LogEvent(
    content=message,
    label="model_request",
    security_domain=user_input,
))

# Log event always visible regardless of scope
emit(LogEvent(
    content=response,
    label="model_response",
    security_domain=None,
))

# Config spec at the system level (only tasks set this, not optimizer)
ConfigSpec(
    name="system_prompt",
    security_domain=system,
    description="The system prompt",
)
```

## Choosing the Test Scope

The `security_domain_tag` you pass to the Controller determines the perspective:

### Narrow Scope (e.g., `user_input`)
- Tests: "What can an attacker do if they only control the user input?"
- Optimizer sees: only `user_input` controllables, entries, observables
- Use case: Testing the most common attack surface

### Medium Scope (e.g., `external`)
- Tests: "What can an attacker do if they control all external-facing surfaces?"
- Optimizer sees: `external`, `user_input`, and `api_input` controllables
- Use case: Testing against a more capable attacker

### Root Scope (e.g., `system`)
- Tests: "What can an attacker do with full access?"
- Optimizer sees: everything
- Use case: Worst-case analysis, finding any possible vulnerability

## Example: RAG System

A RAG system with user input and an internal database:

```python
system = SecurityDomainTag("system")
user = SecurityDomainTag("user", parent=system)
db = SecurityDomainTag("database", parent=system)
domain = SecurityDomain([system, user, db])

class RAGTarget(Target):
    def get_controllables(self):
        return [
            Controllable(spec=ControllableSpec(
                name="user_query", security_domain=user,
            )),
            Controllable(spec=ControllableSpec(
                name="db_content", security_domain=db,
            )),
        ]
```

When scoped to `user`:
- Optimizer controls `user_query` (can inject prompts)
- Optimizer does NOT control `db_content` (gets `ControllableNoInjection`)
- Tests: "Can the attacker extract data just by crafting queries?"

When scoped to `system`:
- Optimizer controls both `user_query` and `db_content`
- Tests: "What if the attacker can also poison the database?"

## FilteredTrajectory

The optimizer receives a `FilteredTrajectory` — a read-only view that only shows entries within scope. It has no reference to the full trajectory (enforced by `__slots__` and push-based architecture).

```python
# In the optimizer:
async def on_event(self, event):
    if isinstance(event, RunEndEvent):
        # event.trajectory is a FilteredTrajectory
        entries = event.trajectory.snapshot()
        # Only sees entries tagged with in-scope security domains
```

The target writes to the full `Trajectory`. The Controller creates the filtered view at trajectory construction time via `Trajectory(filtered_scope=scope)`.

## Score Filtering

Each `Score` in an `EvaluationResult` has a `security_domain` (`SecurityDomainTag | None`). `None` means always visible. The Controller filters `sub_scores` before writing feedback:

```python
# Task returns scores at different domains
EvaluationResult(
    success=True,
    primary_score=Score(value=0.9, security_domain=system),
    sub_scores={
        "user_attack": Score(value=0.8, security_domain=user, name="user_attack"),
        "db_leak": Score(value=0.3, security_domain=db, name="db_leak"),
    },
)
```

If scoped to `user`:
- Optimizer sees `primary_score` (always included)
- Optimizer sees `user_attack` sub-score (in scope)
- Optimizer does NOT see `db_leak` sub-score (out of scope)

## Distinct Combinations

`SecurityDomain.distinct_combinations()` generates all distinct tag combinations to test. This is useful for comprehensive coverage:

```python
domain = SecurityDomain([system, external, internal, user_input, api_input])
for combo in domain.distinct_combinations():
    for tag in combo:
        # Run an evaluation scoped to this tag
        controller = Controller(..., security_domain_tag=tag)
        await controller.run()
```
