# Core Concepts

## The Four Components

Every superred evaluation involves four components:

```
SecurityClaim (collection of Tasks)
    |
    v
Controller (orchestrator)
    |
    +---> Target (the AI system under test)
    |
    +---> Optimizer (the attacker)
```

### Target

The AI system you want to test. A target exposes:

- **Controllables** - injection points the optimizer can manipulate (e.g., user input, database content, API responses). Each has a security domain tag.
- **Observables** - static context the optimizer can read (e.g., system description, model name).
- **Config specs** - settings the task configures before a run (e.g., system prompt, database seed).
- **Query specs** - things the evaluator can query after a run (e.g., last response, logs).
- **`run()`** - executes one interaction, calling `send_event()` at each controllable point.

### Optimizer

The attacker. It receives events through a channel and decides what to inject. The optimizer:

- Gets initialized with the **goal** (what to achieve), **controllables** (what it can control), and **observables** (what it can see).
- Handles events one at a time via `on_event()`.
- Sees `RunStartEvent` at the start of each run, controllable events during the run, and `RunEndEvent` at the end.
- Can signal `done=True` on `RunEndEvent` to stop early (e.g., goal achieved, budget exhausted).

### Task

Defines an adversarial objective. A task:

- Configures the target before runs (e.g., plants a secret in the system prompt).
- Evaluates whether the attack succeeded after each run.
- Returns an `EvaluationResult` with a score and success flag.

Tasks are **stateless** - they don't hold references to the target.

### Security Claim

A collection of tasks. This is what you pass to the Controller. Claims compose:

```python
# Single task
claim = SecurityClaim.from_tasks([task_a])

# Multiple tasks
claim = SecurityClaim.from_tasks([task_a, task_b, task_c])

# Compose claims
combined = SecurityClaim.from_claims([claim_1, claim_2])
```

## The Run Loop

For each task in the security claim, the Controller runs this loop:

```
1. task.configure_target(target)         # set up the scenario
2. optimizer.initialize(goal, ...)       # tell optimizer what to attack
3. LOOP (until optimizer says done or max_runs reached):
   a. Create trajectory
   b. Send RunStartEvent to optimizer
   c. target.run(emit, send_event)
      - Target emits entries via emit() and calls send_event() at controllable points
      - Optimizer responds with injections
      - Controller records events/responses as trajectory entries
   d. Send RunEndEvent to optimizer
      - Optimizer responds with done=True/False
   e. task.evaluate(trajectory, target)  # did the attack work?
   f. target.cleanup()                   # reset for next run
4. optimizer.teardown()
5. target.teardown()
```

## Events and Responses

The target and optimizer communicate through events:

| Event | When | Valid Responses |
|-------|------|-----------------|
| `RunStartEvent` | Before `target.run()` | `EventResponse` |
| `ControllablePreCallEvent` | Target reaches injection point | `ControllableInjection`, `ControllableNoInjection` |
| `ControllablePostCallEvent` | After injection is applied | `ControllableInjection`, `ControllableNoInjection` |
| `RunEndEvent` | After `target.run()` completes | `RunEndResponse(done=True/False)` |

## Trajectory

Every run produces a **trajectory** - an ordered list of `Event | EventResponse` objects recording what happened. Common event types in the trajectory include:

- `LogEvent` - one-way logging from the target (e.g., model requests, model responses). Has `content` and `label` fields.
- `FeedbackEvent` - evaluation result emitted by the controller. Has an `evaluation: EvaluationResult` field.
- `ControllablePreCallEvent` / `ControllablePostCallEvent` - controllable events recorded by the controller.
- `ControllableInjection` / `ControllableNoInjection` - responses to controllable events recorded by the controller.

Lifecycle events (`RunStartEvent`, `RunEndEvent`) are NOT stored in the trajectory.

Each event has a `security_domain` tag (or `None` for events that are always visible regardless of scope). The optimizer sees a **filtered** trajectory that only includes entries within its scope (plus entries with `None` security domain).

## Security Domains

Security domains define trust boundaries. They form a tree:

```
system (root)
  +-- user_input       # what the user controls
  +-- internal_data    # what the system controls internally
```

When the Controller is scoped to `user_input`:
- The optimizer only sees controllables tagged `user_input`
- The optimizer only sees trajectory entries tagged `user_input`
- The optimizer only sees observables tagged `user_input`
- Events for `internal_data` controllables get `ControllableNoInjection` automatically

This lets you test: "What can an attacker achieve if they only control the user input?"

## Scores

Each evaluation produces a `Score` with:
- `value: float` - higher is better
- `security_domain: SecurityDomainTag | None` - which domain this score pertains to (`None` = always visible)
- `name: str` - dimension name (default `"primary"`)

The Controller tracks the best score across runs. Sub-scores outside the active security domain scope are filtered from the optimizer's feedback.
