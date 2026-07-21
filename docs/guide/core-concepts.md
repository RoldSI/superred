---
layout: doc
title: "Core Concepts"
permalink: /guide/core-concepts
---

# Core Concepts

This page defines the vocabulary and shows the loop that ties everything
together. Read it once and the rest of the guide will make sense.

## The five roles

- **SecurityClaim**: a bundle of Tasks (what to test)
  - **Task**: one adversarial objective: set up the target, judge the result
- **Target**: the AI system under test
- **Optimizer**: the attacker
- **Controller**: the orchestrator: runs one threat model

Three of these (Target, Optimizer, SecurityClaim) are things you implement and
ship as separate packages. The Controller is part of the framework; you
construct it but do not subclass it. A Task is the unit inside a claim.

### Target

This is the AI system under test. You wrap it once and reuse it across many
attacks. A target exposes:

- **Controllables**: injection points the attacker may manipulate (the user
  message, a tool's return value, a document fetched from a database, the system
  prompt, ...). Each controllable carries a **security domain** tag.
- **Observables**: facts about the system the attacker is allowed to read (the
  model name, the current system prompt text, ...). Each carries a security
  domain tag too.
- **Config specs**: named slots the *task* may fill in before a run (e.g. which
  tools an agent may call, or the cap on how many messages a run may take). Set
  via `set_config`.
- **Query specs**: named values the *evaluator* may read after a run (e.g. the
  model's final response, the trace of tool calls the agent made, or a snapshot
  of the environment the run left behind). Retrieved via `query`.
- **`run(emit, send_event)`**: executes one interaction. It records facts by
  calling `emit(...)` and pauses at each controllable by calling
  `await send_event(...)` to ask the attacker what to inject.

For example, the `minimal_llm_chat` target wraps a single chat model: its one
controllable is the user message and its one observable is the model's reply. The
`agentdojo` target wraps a whole tool-calling agent, exposing controllables for
the user's task, the system prompt, and the value each tool returns to the agent.

The guiding principle: **build the target to be general and reusable**, and keep
benchmark-specific logic out of it. The chatbot target wraps "any LLM"; the
AgentDojo target wraps "the AgentDojo agent". The specifics of a given benchmark
live in the SecurityClaim, not the target.

See [Writing a Target](/guide/writing-a-target).

### Optimizer

The optimizer is the attacker. It is called an optimizer because it works by
iterating: it makes repeated attempts against the target, optimizing toward its
adversarial goal.

The optimizer and the target run in parallel, and the optimizer acts at its own
pace. When it starts, it is given the **adversarial goal** it is trying to
achieve, the list of **controllables** and **observables** it may use (already
filtered to its scope), and usually an **LLM client**. As the target runs
and reaches each injection point, the optimizer decides what to inject there, and
it decides when to stop. Most optimizers are LLM-driven and call that model to craft their attacks; the
model an optimizer may call and the budget it may spend are fixed by the
experiment, not chosen by the optimizer, because they are part of the threat
model.

For example, the `demo_prompt_list` optimizer replays a fixed list of prompts
into the user-message controllable and calls no model of its own. The `pair`
optimizer is LLM-driven: after each run it reads the model's reply from its
trajectory and asks its own LLM to rewrite the next prompt, iterating toward a
jailbreak.

See [Writing an Optimizer](/guide/writing-an-optimizer).

### Task

A task captures one adversarial objective. It:

- **configures** the target once, before the run loop (e.g. plants a secret, sets a
  benign user goal);
- **evaluates** the trajectory afterwards and returns an `EvaluationResult` with
  a `success` flag and a numeric `primary_score`.

Tasks are **stateless**: they never store a reference to the target. They get
the target handed to them in `configure_target` and again in `evaluate`. This is
what lets a claim be iterated many times.

For example, a secret-leak task plants a secret in the target's system prompt
and marks the run a success if the model reveals it. A HarmBench task hands the
target one harmful instruction and scores whether the model complied.

See [Writing Tasks](/guide/writing-tasks).

### SecurityClaim

A SecurityClaim is a re-iterable collection of tasks. This is what you hand to
the Controller. Claims compose:

```python
claim = SecurityClaim.from_tasks([task_a, task_b, task_c])

# Build a bigger claim out of smaller ones (lazy, re-iterable):
combined = SecurityClaim.from_claims([claim_1, claim_2])
```

In practice you rarely build claims by hand: a module ships a **factory
function** (e.g. `harmbench_claim(...)`, `sorry_bench_claim(...)`) that loads a
dataset and produces one task per prompt.

For example, the `demo_secret_leak` claim is a single hand-written task, while
the `harmbench` claim loads the HarmBench dataset and produces one task for each
harmful behavior in it.

See [Writing Tasks and Security Claims](/guide/writing-tasks).

### Controller = one threat model

A **threat model** is the answer to "what can the attacker do?". In superred it
is captured by three things:

- a **scope**: which security domains (trust boundaries) the attacker controls
  and can observe;
- an **`llm_config`**: which model the attacker may call, and how much it may
  spend;
- **feedback**: whether the attacker learns how its attacks were officially
  scored, or must work from its observables alone.

**One `Controller` instance evaluates one claim under one such threat model.** To compare several threat models (a weak attacker vs a strong
one, with feedback vs without), you build several Controllers. That is covered
in [Running Evaluations](/guide/running-evaluations) and
[Advanced Patterns](/guide/advanced-patterns).

The Controller never shares a target between concurrent tasks: it gets each task
a fresh target from the `target_factory` and a fresh optimizer from the
`optimizer_factory`. The `target_factory` also declares how many tasks may run in
parallel (`concurrency`).

## The run loop

<figure class="evf-figure">
  <div class="evf-box">
    <div class="evf-grid">
      <div class="evf-node evf-optimizer">
        <p class="evf-kicker">Attacker</p>
        <p class="evf-name">Optimizer</p>
        <p class="evf-desc">Acts and observes through events.</p>
      </div>
      <div class="evf-conn evf-conn-left" aria-hidden="true">
        <span class="evf-wire evf-wire-event"><i class="evf-head evf-head-left"></i></span>
        <span class="evf-wire evf-wire-resp"><i class="evf-head evf-head-right"></i></span>
        <span class="evf-tag evf-tag-resp">EventResponse</span>
      </div>
      <div class="evf-controller">
        <div class="evf-ctrl-head">
          <p class="evf-kicker">Framework</p>
          <p class="evf-name">Controller</p>
        </div>
        <div class="evf-subs">
          <div class="evf-sub">
            <p class="evf-sub-name">Threat model</p>
            <p class="evf-sub-note">enforces the scope</p>
          </div>
          <div class="evf-sub">
            <p class="evf-sub-name">Trajectory</p>
            <p class="evf-sub-note">records events &amp; responses</p>
          </div>
        </div>
      </div>
      <div class="evf-conn evf-conn-right" aria-hidden="true">
        <span class="evf-wire evf-wire-event"><i class="evf-head evf-head-left"></i></span>
        <span class="evf-wire evf-wire-resp"><i class="evf-head evf-head-right"></i></span>
        <span class="evf-tag evf-tag-event">Event</span>
      </div>
      <div class="evf-node evf-target">
        <p class="evf-kicker">System</p>
        <p class="evf-name">Target</p>
        <p class="evf-desc">Emits events to expose information and injection points.</p>
      </div>
    </div>
  </div>
</figure>

For each task in the claim, the Controller does this (simplified):

```
trajectory = Trajectory()                 # the record of everything that happens
event_channel = EventChannel()            # the two-way conduit between optimizer and target

target = target_factory.create()          # fresh instance for this task
task.configure_target(target)             # set up the scenario (or skip if NotApplicable)
optimizer = optimizer_factory()           # fresh attacker
optimizer.initialize(
    task.goal,
    target.controllables,
    target.observables,                   # controllables/observables are scope-filtered
    llm_client,
)
launch optimizer.run(event_channel)       # attacker runs concurrently, reading the channel

LOOP (until the optimizer says done, or max_runs_per_task):
    RunStartEvent → optimizer
    target.run() streams events into event_channel:
        every fact it reveals   → recorded on trajectory, forwarded to optimizer
        every injection point   → optimizer decides what to inject
    evaluation = task.evaluate(trajectory, target)   # did it work?
    RunEndEvent(evaluation) → optimizer              # optimizer may answer done=True
    target.reset_ephemeral_state()                   # reset for the next run

optimizer.teardown()
target.teardown()                         # instance is then discarded
```

A "run" is one full pass of the target plus its evaluation. A task can take many
runs: the attacker keeps trying until it gives up (`done=True`), exhausts its
LLM budget, or hits the Controller's `max_runs_per_task` cap (default 100).

## Events and responses

The target and optimizer are strictly separated and never call each other
directly. They communicate through typed **Events** carried on a channel: the
target emits Events as it runs, and the optimizer responds to them. As an
optimizer author, these are the Events you will see:

| Event | When the optimizer sees it | Valid responses |
|-------|----------------------------|-----------------|
| `RunStartEvent` | Just before a new run begins | any `EventResponse` |
| `ControllablePreCallEvent` | Injection point reached, before the tool call | `ControllableInjection`, `ControllableNoInjection` |
| `ControllablePostCallEvent` | Injection point reached, after the tool call, with the official tool result | `ControllableInjection`, `ControllableNoInjection` |
| `RunEndEvent` | Run finished and was evaluated | `RunEndResponse(done=...)` |

`ControllableInjection(value=...)` supplies a value; `ControllableNoInjection`
declines (the target falls back to its own default). The Controller itself sends
`ControllableNoInjection` automatically for any controllable that is **out of
scope**, so the optimizer is never even asked about surfaces it does not control. What
*scope* means, and when a controllable falls out of it, is covered in
[Security domains](#security-domains) below.

There is also a one-way event, `ObservableEvent`, that the *target* emits to
record what happened (the prompt it sent, the response it got, a tool call). The
optimizer does not respond to these; it reads them from the trajectory.

## Trajectory

Every run produces a **trajectory**: an ordered list of `Event | EventResponse`
objects, the single source of truth for what happened. It contains:

- `ObservableEvent`: one-way facts emitted by the target (e.g. the model
  request and the model response). Each has an `observable` (which names it and
  carries its security domain) and a `content` payload.
- `ControllablePreCallEvent` / `ControllablePostCallEvent` and their responses
  (`ControllableInjection` / `ControllableNoInjection`): recorded by the
  Controller around each injection point.
- `RunEndEvent`: written by the Controller after evaluation; it carries the
  `evaluation` result so the optimizer can read feedback from past runs.

`RunStartEvent` is **not** stored in the trajectory (it carries the trajectory
itself and adds nothing as a record). `RunEndEvent` **is** stored.

The optimizer does not see the raw trajectory. It sees a **`FilteredTrajectory`**:
a read-only view containing only entries whose security domain is in scope. The
evaluator, by contrast, sees the
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
modelling decision you make when implementing a target. [Security Domains](/guide/security-domains) is
devoted to it.

## Scores

An `EvaluationResult` carries a `success: bool`, a `primary_score: Score`, a
free-text `rationale` explaining the verdict, and optional named `sub_scores`. A
`Score` has:

- `value: float`: higher is better, and runs from 0 to 1 by convention (the
  framework does not enforce a range);
- `security_domain: SecurityDomainTag | None`: on a sub-score, which boundary it
  pertains to (`None` means always visible); the `primary_score` carries no
  `security_domain`;
- `name: str`: the dimension name (default `"primary"`).

The Controller tracks the best primary score across a task's runs. `sub_scores`
carrying an out-of-scope `security_domain` are filtered out of the feedback the
optimizer sees (an untagged sub-score, `security_domain=None`, stays visible);
the `primary_score`, `success`, and `rationale` are always shown, because the
attacker needs the main signal to improve.
