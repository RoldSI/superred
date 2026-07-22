---
layout: doc
title: "Target"
permalink: /reference/target
---

# Target

A **target** is the AI system under test, wrapped so the framework can drive it: a
chatbot, a tool-using agent, a sandboxed application. A target is a **passive**
attack surface, not an adversary. Its one job is to expose, faithfully and in
full, everything an attacker might touch or observe, and then to run.

You write a target by subclassing `Target` and implementing its surfaces and
lifecycle. The guiding principle is to keep a target **general and reusable**:
wrap "any LLM" or "the AgentDojo agent," and leave benchmark-specific goals and
judging to the [Task](/reference/task) and [SecurityClaim](/reference/security-claim).

## The five surfaces

A target exposes its system through five kinds of surface. Two are for setup and
evaluation (a task and an evaluator use them, off the event loop); two are the
attacker-facing surfaces; one is the trust-boundary map.

| Surface | Who uses it | When |
|---------|-------------|------|
| **Config** (`config_specs` / `set_config`) | the Task | before a run |
| **Query** (`query_specs` / `query`) | the evaluator | after a run |
| **Controllables** (`get_controllables`) | the Optimizer | during a run (inject) |
| **Observables** (`get_observables`) | the Optimizer | before a run (read static context) |
| **Security domain** (`security_domain`) | the Controller | to filter by scope |

Each piece of information is exposed **exactly once**. A tool call the attacker can
tamper with is a controllable (never also an observable); a fact the attacker only
reads is an observable; a live event during a run goes on the trajectory as an
`ObservableEvent`, not into `get_observables`. Static facts about the setup belong
to `get_observables`; the live trace belongs on the trajectory.

## Manual values (constructor)

API keys, credentials, and other user-provided secrets are passed **directly to
the constructor**, not through any framework surface. This keeps the interface
clean and instantiation explicit:

```python
target = MyDockerTarget(api_key="sk-...", image="my-app:latest")
```

A target runs inference with its own provider client, not the optimizer's
`LLMClient`, so its own token spend is out of band and uncounted against the
attacker's budget.

## Pre-run configuration (task-set)

- `config_specs -> list[ConfigSpec]` declares named, text-valued config slots,
  each with a security domain. Each spec's description is the format contract.
- `set_config(name, value)` accepts a config value before a run.

A task uses these to set up the scenario (plant a secret, set a benign user goal).
A config slot is **never** an attacker surface: only the task sets it. Model
identity and generation settings stay out of config; they are construction
concerns, fixed for an experiment.

## Post-run queries (evaluator-used)

- `query_specs -> list[QuerySpec]` declares named post-run interactions (a name, a
  description, optional params).
- `query(name, **params) -> str` executes one. A simple getter takes no params;
  an action ("search the database for X") declares them.

Config and query are **intentionally distinct**: config is task-set pre-run state;
query is post-run ground truth, which may differ from what was configured.

## Attacker-facing surfaces

- `get_controllables() -> list[Controllable]` the injection points the optimizer
  may manipulate during a run. Each carries a
  [security-domain tag](/reference/security-domains). Controllables are everything
  relevant an attacker could meddle with: a system prompt, the user input, a tool's
  return value, a retrieved document, memory carried across runs.
- `get_observables() -> list[ObservableValue]` static context the optimizer may
  read (the model name, the system prompt text, a tool catalogue). Each carries a
  tag.

The Controller filters both by scope before the optimizer sees them, so a target
always returns its **full** set and lets the threat model decide what is visible.

## Security domain

- `security_domain -> SecurityDomain` the target's
  [trust-boundary forest](/reference/security-domains). It classifies every
  controllable and observable into a hierarchy the Controller filters by. Designing
  this forest is the most consequential modelling decision a target author makes;
  the guide's [Security Domains](/guide/security-domains) page works through it.

## Execution and the state lifecycle

- `async run(emit, send_event)` executes one run. Record facts with
  `emit(ObservableEvent(observable=..., content=...))` (fire-and-forget), and pause
  at each controllable with `await send_event(ControllablePreCallEvent(...))`,
  using the returned response. The target receives only these two callbacks (typed
  [`EventHandler` and `EventResponseHandler`](/reference/events-and-trajectory#callback-type-aliases)),
  not the trajectory object, so it can record but not read or close it.
- `async reset_ephemeral_state()` reset per-run state after each evaluation.
- `async teardown()` release external resources when all evaluation is done.

A target has **three state lifetimes**, and getting them right is what makes
multi-run and cross-run attacks work:

- **Ephemeral** per-run state (the active conversation, the last response). Reset
  by `reset_ephemeral_state()` after **every** run.
- **Durable** state that must persist across runs within a task (a memory bank an
  attack accumulates across attempts). **Not** reset by `reset_ephemeral_state()`;
  discarded only when the next task gets a fresh instance from the factory.
- **Resources / identity** the configured definition and external handles.
  Constant for the instance's lifetime; released in `teardown()`.

The instance lifecycle the Controller drives:

{% include diagrams/d7.html %}

`reset_ephemeral_state()` must be implemented even if it is a no-op: making it
explicit forces the author to decide, per field, what is ephemeral and what
survives.

## Internal parallelism and thread bridging

A target may run inference concurrently. It may spawn branches that each call
`send_event` independently (each suspends only its own branch), and a thread-backed
target (Docker, a subprocess) may bridge blocking work back to the loop with
`asyncio.run_coroutine_threadsafe`. Target instances carry no concurrency cap of
their own; the [`TargetFactory`](/reference/controller#targetfactory) decides how
many run in parallel. The patterns and examples are in
[Events, Channel & Trajectory](/reference/events-and-trajectory#concurrency-model).

## A minimal shape

```python
class MyChatTarget(Target):
    def __init__(self, api_key: str, model: str) -> None:
        self._api_key, self._model = api_key, model
        self._system_prompt = ""
        self._last_response = ""

    @property
    def config_specs(self):
        return [ConfigSpec("system_prompt", SYSTEM_TAG, "The system prompt")]

    def set_config(self, name, value):
        if name == "system_prompt":
            self._system_prompt = value

    @property
    def query_specs(self):
        return [QuerySpec("last_response", "The model's most recent reply")]

    def query(self, name, **params):
        return self._last_response

    @property
    def security_domain(self):
        return SecurityDomain([SYSTEM_TAG, USER_TAG])

    def get_controllables(self):
        return [Controllable("chat_message", USER_TAG, "The user's message")]

    def get_observables(self):
        return [ObservableValue(Observable("model", SYSTEM_TAG, "Model id"), self._model)]

    async def run(self, emit, send_event):
        pre = ControllablePreCallEvent(
            controllable=self.get_controllables()[0], request="",
        )
        resp = await send_event(pre)                       # ask the attacker
        message = resp.value if isinstance(resp, ControllableInjection) else ""
        emit(ObservableEvent(observable=..., content=message))
        self._last_response = await self._call_model(self._system_prompt, message)
        emit(ObservableEvent(observable=..., content=self._last_response))

    async def reset_ephemeral_state(self):
        self._last_response = ""                            # ephemeral only

    async def teardown(self):
        ...                                                 # close clients, etc.
```

## Design decisions

- **Manual values at construction.** No `set_manual` in the interface; the target
  validates its own constructor arguments.
- **Config and query are separate.** Different actors (task vs evaluator),
  different lifecycles (pre-run vs post-run), different security concerns.
- **Values are always text.** Config and query use strings; the description
  documents the format, and the target interprets it.
- **`send_event` and `emit` are callbacks.** The target is decoupled from the
  optimizer and the channel; the same target works with any Controller wiring.
- **`reset_ephemeral_state` is required.** Even as a no-op, it forces an explicit
  decision about inter-run state, which is what makes durable-memory attacks
  possible.
