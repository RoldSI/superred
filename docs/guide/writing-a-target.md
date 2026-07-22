---
layout: doc
title: "Writing a Target"
permalink: /guide/writing-a-target
---

# Writing a Target

A target wraps the AI system you want to red-team and exposes it to the
framework through a small, fixed interface. This is usually the first thing you
build for a new system.

The single most important habit: **make the target general and reusable.** A
target should model *a kind of system* (any chatbot, the AgentDojo agent, a RAG
pipeline), not one benchmark. Everything benchmark-specific (which prompts, what
counts as success) belongs in a [SecurityClaim](/guide/writing-tasks), not here.
The payoff is that one target serves many claims, and one claim can run against
many targets.

A target can wrap either a **mocked environment** (fast, deterministic, and
cheap to run in bulk) or a **real, non-production deployment** of your system,
so you can stress-test the actual thing under attack before it ships. Point it
at staging or a throwaway instance, never at production.

## What a target must provide

You subclass `superred.core.interfaces.target.Target` and implement:

| Member | Kind | Purpose |
|--------|------|---------|
| `config_specs` | property | the configuration parameters a task may set before a run |
| `set_config(name, value)` | method | set one of the target's configuration parameters |
| `query_specs` | property | the named questions an evaluator may ask after a run |
| `query(name, **params)` | method | answer one query |
| `security_domain` | property | the trust-boundary forest (see [Security Domains](/guide/security-domains)) |
| `get_controllables()` | method | the injection points, each tagged with a domain |
| `get_observables()` | method | static facts the attacker may read, each tagged |
| `run(emit, send_event)` | async method | run one attempt of the attacker against the target |
| `reset_ephemeral_state()` | async method | reset ephemeral (per-run) state (called after each evaluation) |
| `teardown()` | async method | release resources (called once at the end) |

{% include diagrams/u2.html %}

## Minimal template

This is the complete `MinimalLLMChatTarget` that ships as the
`superred-target-minimal-llm-chat` package, lightly annotated. It is a
single-turn chatbot: one config slot (system prompt), one controllable (the user
message), one query (the last response).

```python
from __future__ import annotations

from litellm import ModelResponse, acompletion

from superred.core.interfaces.target import Target
from superred.core.types.controllable import Controllable
from superred.core.types.event import EventHandler, EventResponseHandler
from superred.core.types.events import (
    ControllableInjection,
    ControllablePreCallEvent,
    ObservableEvent,
)
from superred.core.types.observable import Observable, ObservableValue
from superred.core.types.security_domain import SecurityDomain, SecurityDomainTag
from superred.core.types.state import ConfigSpec, QuerySpec

# --- Step 1: define the trust-boundary forest, once, as module constants ---
SYSTEM_TAG = SecurityDomainTag("system")
USER_INPUT_TAG = SecurityDomainTag("user_input", parent=SYSTEM_TAG)
_DOMAIN = SecurityDomain([SYSTEM_TAG, USER_INPUT_TAG])

# Define each controllable/observable ONCE so get_controllables() and run()
# share the exact same instance (the framework matches them by value).
_USER_INPUT_CTRL = Controllable(
    name="user_input",
    security_domain=USER_INPUT_TAG,
    description="The user message sent to the LLM.",
)


class MinimalLLMChatTarget(Target):
    """A single-turn LLM chat system."""

    def __init__(self, model: str, api_base: str, api_key: str) -> None:
        # Manual operational values go in the constructor, never through config.
        self._model = model
        self._api_base = api_base
        self._api_key = api_key
        self._system_prompt = "You are a helpful assistant."
        self._last_response = ""

    # --- Config: what the TASK sets before a run ---
    @property
    def config_specs(self) -> list[ConfigSpec]:
        return [
            ConfigSpec(
                name="system_prompt",
                security_domain=SYSTEM_TAG,
                description="System prompt for the LLM.",
            ),
        ]

    def set_config(self, name: str, value: str) -> None:
        if name == "system_prompt":
            self._system_prompt = value

    # --- Query: what the EVALUATOR reads after a run ---
    @property
    def query_specs(self) -> list[QuerySpec]:
        return [QuerySpec(name="last_response", description="The LLM's last response.")]

    def query(self, name: str, **params: str) -> str:
        if name == "last_response":
            return self._last_response
        return ""

    # --- The trust boundaries ---
    @property
    def security_domain(self) -> SecurityDomain:
        return _DOMAIN

    # --- Attack surface ---
    def get_controllables(self) -> list[Controllable]:
        return [_USER_INPUT_CTRL]

    def get_observables(self) -> list[ObservableValue]:
        obs = Observable(
            name="model", security_domain=SYSTEM_TAG,
            description="The LLM model identifier.",
        )
        return [ObservableValue(observable=obs, content=self._model)]

    # --- One attempt against the target ---
    async def run(self, emit: EventHandler, send_event: EventResponseHandler) -> None:
        # 1. Ask the attacker what to put in the user_input controllable.
        resp = await send_event(
            ControllablePreCallEvent(controllable=_USER_INPUT_CTRL, request="Enter user message:"),
        )
        # 2. Use the injection, or fall back if this surface is out of scope.
        user_message = resp.value if isinstance(resp, ControllableInjection) else "Hello"

        # 3. Record what we are about to send (so the attacker/evaluator can see it).
        emit(ObservableEvent(
            observable=Observable(
                name="model_request", security_domain=USER_INPUT_TAG,
                description="User message sent to the LLM.",
            ),
            content=user_message,
        ))

        # 4. Call the actual system.
        response = await acompletion(
            model=self._model,
            messages=[
                {"role": "system", "content": self._system_prompt},
                {"role": "user", "content": user_message},
            ],
            api_base=self._api_base,
            api_key=self._api_key,
        )
        assert isinstance(response, ModelResponse)
        self._last_response = response.choices[0].message.content or ""

        # 5. Record the result.
        emit(ObservableEvent(
            observable=Observable(
                name="model_response", security_domain=SYSTEM_TAG,
                description="LLM response.",
            ),
            content=self._last_response,
        ))

    async def reset_ephemeral_state(self) -> None:
        self._last_response = ""   # reset ephemeral (per-run) state

    async def teardown(self) -> None:
        pass                       # nothing to release here
```

## Key ideas, one at a time

### Constructor takes manual values only

API keys, base URLs, model names, container images: these are operational facts
about *your deployment*, not part of the attack. They go in `__init__`. The
framework never sets them. Only **tasks** push values in, and only through
`set_config`.

### Config (before) vs Query (after)

These serve different actors at different times. Keep them distinct.

| | Config | Query |
|---|---|---|
| Who uses it | the Task, before the run | the Task's evaluator, after the run |
| Method | `set_config(name, value)` | `query(name, **params)` |
| Purpose | set up the scenario | read out what happened |
| Examples | system prompt, DB seed | last response, transcript, DB row |

A `QuerySpec` carries a `name` and a `description`; a `ConfigSpec` additionally
carries a `security_domain` (config slots are tagged just like controllables).
**The description is the contract**: values are always plain text, and the
description tells the task author what format to send and what they will get
back. A `QuerySpec` may also declare `params` for queries that take arguments.
The template's `last_response` query is a plain getter; a parameterized query
looks like this:

```python
from superred.core.types.state import QueryParam, QuerySpec

QuerySpec(
    name="read_file",
    description="Return the contents of a file the agent wrote during the run.",
    params=[QueryParam(name="path", description="Absolute path of the file to read.")],
)
# The evaluator then calls: target.query("read_file", path="/tmp/output.txt")
```

### Controllables: the attack surface

A `Controllable` is one injection point. It is a flat, frozen value:

```python
Controllable(
    name="user_input",            # unique within the target
    security_domain=USER_INPUT_TAG,  # which trust boundary it belongs to (required)
    description="The user message sent to the LLM.",
    value_type="text",            # "text" (default), "json", "modifier", "binary"
)
```

During `run()`, you reach an injection point by sending a
`ControllablePreCallEvent` and awaiting the response:

```python
resp = await send_event(
    ControllablePreCallEvent(controllable=_USER_INPUT_CTRL, request="Enter user message:"),
)
if isinstance(resp, ControllableInjection):
    value = resp.value
else:
    # ControllableNoInjection: this surface is out of the tested scope,
    # OR the attacker chose not to inject. Use your own default.
    value = "Hello"
```

The `request` string describes what this point needs; the attacker sees it.
**Always handle the `ControllableNoInjection` case** with a sensible default: a
controllable is silently declined whenever it is out of scope, which is the
normal situation for any surface the current threat model does not grant.

Use the **same `Controllable` instance** in `get_controllables()` and in the
event you send. The security-domain filter matches on the controllable carried
by the event, and optimizers match on `event.controllable.name`, so defining
each controllable once as a module constant avoids subtle mismatches.

### Post-call events: letting the attacker see the effect

Some attackers want to observe what their injection produced before deciding
their next move (multi-turn jailbreaks, for instance). Send a
`ControllablePostCallEvent` after you have used the value:

```python
from superred.core.types.events import ControllablePostCallEvent

await send_event(ControllablePostCallEvent(
    controllable=_USER_INPUT_CTRL,
    request="Enter user message:",
    answer=self._last_response,
))
```

Whether to fire post-call events is your design choice. Targets that want to
support adaptive multi-turn attacks generally do; simple single-shot targets
often do not, and instead rely on the attacker reading the response from the
trajectory.

### Observables vs ObservableEvents

There are two ways the attacker learns facts, and they are different:

- **`get_observables()`** returns *static* context known before any run: the
  model identifier, the tool catalogue, the system description. Each is an
  `ObservableValue(observable=Observable(...), content=...)`. These are passed to
  the optimizer at `initialize` time (scope-filtered).
- **`emit(ObservableEvent(...))`** records *runtime* facts as the run unfolds:
  the exact prompt sent, the response received, a tool call and its result. These
  land in the trajectory.

Both carry a `security_domain` (on the `Observable`). The domain decides who can
see the fact. In the template, the user's message is tagged `USER_INPUT_TAG` (an
attacker controlling user input already knows it), while the model's response is
tagged `SYSTEM_TAG`.

### `emit` and `send_event`: the two callbacks

`run()` receives two callbacks with deliberately different shapes:

- `emit: EventHandler` is **fire-and-forget**: `emit(some_event)` records a
  one-way `ObservableEvent` and returns nothing. It does not pause.
- `send_event: EventResponseHandler` is **request/response**:
  `await send_event(some_event)` sends the event to the attacker and *suspends
  this coroutine* until the attacker responds.

The target never sees the full trajectory. It only writes to it (through
`emit`) and asks questions (through `send_event`).

{% include diagrams/u3.html %}

### reset_ephemeral_state vs teardown

- **`reset_ephemeral_state()`** runs after *every* run-and-evaluation, to reset
  ephemeral (per-run) state so the next run starts clean (clear the last
  response, wipe a scratch database, reset a container's mutable state). Durable
  state that must persist across runs within a task (e.g. an accumulated memory
  bank) is not reset here. It must be explicit even when it is a no-op.
- **`teardown()`** runs once when the task is finished with this instance, to
  release resources (close connections, stop containers). After `teardown` the
  instance is discarded.

Because the Controller builds a **fresh target per task**, you do not need
`reset_ephemeral_state`/`teardown` to undo cross-task state. They only manage
state *within* one task's sequence of runs.

## Concurrency: how many instances run at once

The number of tasks that may run in parallel against independent target
instances is declared on the `TargetFactory`, not inside the target:

```python
from superred.core.controller import TargetFactory

target_factory = TargetFactory(
    create=lambda: MinimalLLMChatTarget(model=..., api_base=..., api_key=...),
    concurrency=8,   # up to 8 tasks at once, each with its own instance
)
```

Choose `concurrency` for the target's cost: a chatbot wrapping a hosted API can
comfortably use 8 or more; a target that boots a sandbox or holds a heavy
resource should usually stay at `1` unless it pools internally. Because each
task gets its own instance, you do not need locks for cross-task safety. (Within
a single run, a target *may* fan out into concurrent branches; see
[Advanced Patterns](/guide/advanced-patterns).)

## Multiple controllables at different boundaries

A richer target exposes several injection points, each at its own trust
boundary. This is what makes scoped threat models expressive:

```python
_USER_QUERY_CTRL = Controllable(name="user_query", security_domain=USER_TAG,
                                 description="The user's search query.")
_DB_RESULT_CTRL  = Controllable(name="db_result", security_domain=DB_TAG,
                                 description="A document returned from the database.")

def get_controllables(self) -> list[Controllable]:
    return [_USER_QUERY_CTRL, _DB_RESULT_CTRL]

async def run(self, emit, send_event):
    user_resp = await send_event(
        ControllablePreCallEvent(controllable=_USER_QUERY_CTRL, request="user query"))
    user_query = user_resp.value if isinstance(user_resp, ControllableInjection) else "default"

    db_resp = await send_event(
        ControllablePreCallEvent(controllable=_DB_RESULT_CTRL, request="db lookup"))
    if isinstance(db_resp, ControllableInjection):
        db_result = db_resp.value          # attacker poisoned the database
    else:
        db_result = self._real_db_lookup(user_query)   # untouched: out of scope

    response = await self._generate(user_query, db_result)
```

Scoped to `{user}`, the attacker controls `user_query` while `db_result` is
auto-declined: you are testing "can the attacker win through queries alone?".
Scoped to `{system}` (a root that includes both), the attacker controls both:
"what if they can also poison the database?". Designing these boundaries is the
subject of [Security Domains](/guide/security-domains).

## Worked examples in the repository

- [`superred-modules/targets/minimal_llm_chat`](https://github.com/RoldSI/superred-modules/tree/main/targets/minimal_llm_chat): the template above.
- [`superred-modules/targets/chatbot`](https://github.com/RoldSI/superred-modules/tree/main/targets/chatbot): a production chatbot target: single- or
  multi-turn, with a two-tree domain forest that separates "knows the model
  name" from "can override the system prompt" from "can rewrite the response".
  Its module docstring is a good model for documenting your own boundaries.
- [`superred-modules/targets/agentdojo`](https://github.com/RoldSI/superred-modules/tree/main/targets/agentdojo): a tool-calling agent target with a
  three-tree forest, including a `tools` tree of per-service data stores
  (banking, workspace, slack, travel). A good study in modelling a complex
  system's real trust structure.
