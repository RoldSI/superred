# Core Concepts

This page defines the vocabulary and shows the loop that ties everything
together. Read it once and the rest of the guide will make sense.

## The five roles

```
SecurityClaim   = a bundle of Tasks (what to test)
  Task          = one adversarial objective: set up the target, judge the result
Target          = the AI system under test
Optimizer       = the attacker
Controller      = the orchestrator: runs ONE threat model
```

Three of these (Target, Optimizer, SecurityClaim) are things you implement and
ship as separate packages. The Controller is part of the framework; you
construct it but do not subclass it. A Task is the unit inside a claim.

### Target

The AI system you want to test. You wrap your system once and reuse it across
many attacks. A target exposes:

- **Controllables** - injection points the attacker may manipulate (the user
  message, a tool's return value, a document fetched from a database, the system
  prompt, ...). Each controllable carries a **security domain** tag.
- **Observables** - facts about the system the attacker is allowed to read (the
  model name, the current system prompt text, ...). Each carries a security
  domain tag too.
- **Config specs** - named slots the *task* fills in before a run (e.g. the
  system prompt, a database seed). Set via `set_config`.
- **Query specs** - named questions the *evaluator* asks after a run (e.g. "what
  was the last response?"). Answered via `query`.
- **`run(emit, send_event)`** - executes one interaction. It records facts by
  calling `emit(...)` and pauses at each controllable by calling
  `await send_event(...)` to ask the attacker what to inject.

The guiding principle: **build the target to be general and reusable**, and keep
benchmark-specific logic out of it. The chatbot target wraps "any LLM"; the
AgentDojo target wraps "the AgentDojo agent". The specifics of a given benchmark
live in the SecurityClaim, not the target. See [Writing a Target](03-writing-a-target.md).

### Optimizer

The attacker. It is an **actor**: the Controller launches `optimizer.run(channel)`
as its own concurrent `asyncio` task, and the optimizer pulls events off the
channel at its own pace. Most optimizers inherit the default `run()` and just
implement `on_event(event)`, a small state machine that reacts to each event.
The optimizer:

- is `initialize`d with the **goal**, the **controllables** and **observables**
  it is allowed to see (already filtered to its scope), and an **LLM client**;
- handles events one at a time: a `RunStartEvent`, then a controllable event for
  each injection point the target reaches, then a `RunEndEvent`;
- decides what to inject at each controllable, and whether to **stop** (by
  returning `done=True` on the `RunEndEvent`);
- may call `self.llm.complete(...)` to generate attacks, *if* the experiment
  granted it an LLM. The model and the spending budget are chosen by the
  experiment, not by the optimizer: that is part of the threat model.

See [Writing an Optimizer](04-writing-an-optimizer.md).

### Task

One adversarial objective. A task:

- **configures** the target before each run (e.g. plants a secret, sets a
  benign user goal);
- **evaluates** the trajectory afterwards and returns an `EvaluationResult` with
  a `success` flag and a numeric `primary_score`.

Tasks are **stateless**: they never store a reference to the target. They get
the target handed to them in `configure_target` and again in `evaluate`. This is
what lets a claim be iterated many times. See [Writing Tasks](05-writing-tasks.md).

### SecurityClaim

A re-iterable collection of tasks. This is what you hand to the Controller.
Claims compose:

```python
from superred.core.interfaces.security_claim import SecurityClaim

claim = SecurityClaim.from_tasks([task_a, task_b, task_c])

# Build a bigger claim out of smaller ones (lazy, re-iterable):
combined = SecurityClaim.from_claims([claim_1, claim_2])
```

In practice you rarely build claims by hand: a module ships a **factory
function** (e.g. `harmbench_claim(...)`, `sorry_bench_claim(...)`) that loads a
dataset and produces one task per prompt. See [Writing Tasks and Security
Claims](05-writing-tasks.md).

### Controller = one threat model

A **threat model** is the answer to "what can the attacker do?". In superred it
is captured by two things:

- a **scope**: which security domains (trust boundaries) the attacker controls
  and can observe;
- an **`llm_config`**: which model the attacker may call, and how much it may
  spend.

**One `Controller` instance evaluates one claim under one `(scope, llm_config)`
threat model.** To compare several threat models (a weak attacker vs a strong
one, with feedback vs without), you build several Controllers. That is covered
in [Running Evaluations](06-running-evaluations.md) and
[Advanced Patterns](08-advanced-patterns.md).

The Controller never shares a target between concurrent tasks: it gets each task
a fresh target from the `TargetFactory` and a fresh optimizer from the
`optimizer_factory`. The factory also declares how many tasks may run in
parallel (`concurrency`).

## The run loop

For each task in the claim, the Controller does this (simplified):

```
target = target_factory.create()          # fresh instance for this task
task.configure_target(target)              # set up the scenario (or skip if NotApplicable)
optimizer = optimizer_factory()            # fresh attacker
optimizer.initialize(goal, controllables, observables, llm_client)
                                           # controllables/observables are scope-filtered
launch optimizer.run(channel)              # attacker runs concurrently

LOOP (until the optimizer says done, or max_runs_per_task):
    send RunStartEvent  ->  optimizer
    target.run(emit, send_event):
        target emits ObservableEvent facts via emit(...)
        target pauses at each controllable: send_event(...) -> optimizer injects
    evaluation = task.evaluate(trajectory, target)   # did it work?
    send RunEndEvent(evaluation)  ->  optimizer       # optimizer may answer done=True
    target.reset_ephemeral_state()                    # reset for the next run

optimizer.teardown()
target.reset_ephemeral_state(); target.teardown()        # instance is then discarded
```

A "run" is one full pass of the target plus its evaluation. A task can take many
runs: the attacker keeps trying until it gives up (`done=True`), exhausts its
budget, or hits the Controller's `max_runs_per_task` safety cap (default 100).

## Events and responses

The target and optimizer never call each other directly. They communicate
through typed **events** carried on a channel. As an optimizer author, these are
the events you will see:

| Event | When the optimizer sees it | Valid responses |
|-------|----------------------------|-----------------|
| `RunStartEvent` | Just before a new run begins | any `EventResponse` |
| `ControllablePreCallEvent` | Target reached an injection point | `ControllableInjection`, `ControllableNoInjection` |
| `ControllablePostCallEvent` | Target finished using an injection (lets you observe the effect) | `ControllableInjection`, `ControllableNoInjection` |
| `RunEndEvent` | Run finished and was evaluated | `RunEndResponse(done=...)` |

`ControllableInjection(value=...)` supplies a value; `ControllableNoInjection`
declines (the target falls back to its own default). The Controller itself sends
`ControllableNoInjection` automatically for any controllable that is **out of
scope**, so the optimizer is never even asked about surfaces it does not control.

There is a second one-way event, `ObservableEvent`, that the *target* emits to
record what happened (the prompt it sent, the response it got, a tool call). The
optimizer does not respond to these; it reads them from the trajectory.

## Trajectory

Every run produces a **trajectory**: an ordered list of `Event | EventResponse`
objects, the single source of truth for what happened. It contains:

- `ObservableEvent` - one-way facts emitted by the target (e.g. the model
  request and the model response). Each has an `observable` (which names it and
  carries its security domain) and a `content` payload.
- `ControllablePreCallEvent` / `ControllablePostCallEvent` and their responses
  (`ControllableInjection` / `ControllableNoInjection`) - recorded by the
  Controller around each injection point.
- `RunEndEvent` - written by the Controller after evaluation; it carries the
  `evaluation` result so the optimizer can read feedback from past runs.

`RunStartEvent` is **not** stored in the trajectory (it carries the trajectory
itself and adds nothing as a record). `RunEndEvent` **is** stored.

The optimizer does not see the raw trajectory. It sees a **`FilteredTrajectory`**:
a read-only view containing only entries whose security domain is in scope (plus
entries explicitly tagged with no domain). The evaluator, by contrast, sees the
full unfiltered trajectory.

## Security domains

A security domain is a **trust boundary**: a labelled surface that an attacker
either does or does not control. The target defines them as a tree (or a forest
of independent trees). A parent tag *includes* all its descendants.

```
system                 (root: full control of the system)
  ├── system_prompt     (can override the system prompt)
  └── user              (can send user messages)
```

When you scope a Controller to `{user}`, the Controller filters **everything the
optimizer can see or touch** to that boundary:

- only `user` controllables are offered to it,
- only `user` observables are passed to it,
- its trajectory view contains only `user`-tagged entries,
- evaluation sub-scores outside `user` are hidden,
- and any out-of-scope controllable is auto-answered `ControllableNoInjection`.

This is how you ask precise questions like *"what can an attacker achieve if they
control only the user message, and nothing else?"* Choosing these boundaries
well, based on the real trust structure of the system, is the most important
modelling decision you make. [Security Domains](07-security-domains.md) is
devoted to it.

## Scores

An `EvaluationResult` carries a `success: bool`, a `primary_score: Score`, and
optional named `sub_scores`. A `Score` has:

- `value: float` - higher is better (the scale is whatever the task defines);
- `security_domain: SecurityDomainTag | None` - on a sub-score, which boundary it
  pertains to (`None` means always visible); the `primary_score` carries no
  `security_domain`;
- `name: str` - the dimension name (default `"primary"`).

The Controller tracks the best primary score across a task's runs. `sub_scores`
carrying an out-of-scope `security_domain` are filtered out of the feedback the
optimizer sees (an untagged sub-score, `security_domain=None`, stays visible);
the `primary_score`, `success`, and `rationale` are always shown, because the
attacker needs the main signal to improve. The `primary_score` is never
scope-filtered: it is the unscoped optimization signal.
