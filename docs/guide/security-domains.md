---
layout: doc
title: "Security Domains"
permalink: /guide/security-domains
---

# Security Domains

A security domain is a **trust boundary**: a labelled surface that an attacker
either controls (and can observe) or does not. Designing a target's domains is
the most consequential modelling decision you make, because it determines which
questions you can ask. This page explains the mechanics and, more importantly,
the first principles that the shipped targets follow when they map a real
system's trust structure onto domains.

## What a domain does

The target defines its domains as a **forest**: one or more trees of
`SecurityDomainTag` nodes. Each controllable, observable, config slot, and
trajectory entry is tagged with one tag. A parent tag **includes** all of its
descendants.

You evaluate at a **scope**: a `frozenset` of tags. When you scope a Controller,
it filters everything the optimizer can see or do, on five fronts:

| What | How it is filtered |
|------|--------------------|
| Controllables | only the **injectable** ones (in `scope`) are passed to `optimizer.initialize()` |
| Observables | in-scope observables are passed to `optimizer.initialize()`, **plus** read-only controllables re-presented as observables (visible but not injectable) |
| Events | out-of-scope controllable events are auto-answered `ControllableNoInjection`; so are in-scope events under a `read_only` tag (those stay visible on the trajectory) |
| Trajectory | the optimizer sees a `FilteredTrajectory` with only in-scope entries |
| Feedback sub-scores | tagged out-of-scope sub-scores are dropped; untagged sub-scores, primary, success, and rationale are always shown |

So scoping to `{user}` literally constructs the experiment "what can an attacker
achieve controlling only the user input, seeing only what a user-input attacker
would see?".

## The `includes` relationship

```python
from superred.core.types.security_domain import SecurityDomain, SecurityDomainTag

system   = SecurityDomainTag("system")
external = SecurityDomainTag("external", parent=system)
user     = SecurityDomainTag("user", parent=external)
api      = SecurityDomainTag("api", parent=external)
domain   = SecurityDomain([system, external, user, api])   # validates the forest

system.includes(user)     # True  - ancestor includes descendant
external.includes(api)    # True
external.includes(system) # False - descendant does not include ancestor
external.includes(user)   # True
user.includes(user)       # True  - a tag includes itself
```

`scope_includes(scope, tag)` is `True` when **any** tag in the scope includes
`tag`. An out-of-scope surface is one no scope member covers.

## Access levels: read-only surfaces

`scope` is what the attacker can **read and write** (see and inject into). A
second, optional Controller argument, `read_only`, adds tags it can **only
read**. `read_only` defaults to empty, so the whole `scope` is read & write (the
classic behavior). Tags listed under `read_only` stay visible (their events are
recorded on the trajectory and shown through every filtered surface), but the
Controller answers their controllable events with `ControllableNoInjection`
without consulting the optimizer.

```python
controller = Controller(
    scope=frozenset({api}),         # only the api subtree is read & write
    read_only=frozenset({system}),  # the whole system tree is visible, read-only
    ...
)
```

Two rules govern the relationship:

- **Read & write overrules read-only.** Only `scope` drives the injection
  decision, so a `read_only` tag already inside `scope`'s subtree has no effect
  (it stays injectable). The useful pattern is the reverse: a read & write
  `scope` tag inside a `read_only` ancestor's subtree, like `api` above, makes
  just that subtree injectable while the rest stays visible.
- **Default is all-read & write.** Omit `read_only` and every tag in `scope` is
  injectable. `scope` and `read_only` cannot both be empty.

Use this instead of declaring separate `*_readable` subtags on the target: the
target emits each piece of information exactly once, and whether an attacker
can merely see it or also tamper with it is decided per threat model at the
Controller.

How the optimizer sees the split: at `initialize()` it gets a `controllables`
list (exactly the surfaces it can inject into) and an `observables` list (what
it can read). A read-only controllable is therefore **shown to the optimizer as
an observable**, not a controllable, honest by construction, since for this run
it is a thing you read, not a thing you inject. Its runtime values still arrive
on the trajectory as its (declined) controllable events.

## First principles for mapping real trust boundaries

These are the rules of thumb the chatbot and AgentDojo targets follow. They turn
"draw some boxes" into a disciplined model.

**1. Name a domain by the capability it grants, not by an attacker persona.**
Tags like `system_prompt`, `tool_catalogue`, `user`, `response` describe *what
can be touched*. The persona ("a malicious user", "a compromised plugin") is an
emergent reading of a *scope*, not a tag.

**2. Make a child mean "a strictly weaker capability."** Parent-includes-child
should encode capability subsumption: if holding A automatically gives you B,
make B a child of A. In AgentDojo, `tool_catalogue` (full edit: replace,
unregister, rewrite) includes `tool_catalogue_addable` (register-only, the
weakest write). Granting the strong capability in a scope automatically grants
the weak ones.

**3. Read-only is a scope decision, not a tag.** Being able to change something
implies being able to see it, so don't model "see only" as extra tags: declare
one tag per surface, emit the information once, and grant weaker attackers
visibility by listing the tag under `read_only` instead of `scope`. "Can read
the system prompt but not change it" is `read_only={system_prompt, ...}`; "can
override it" is `scope={system_prompt, ...}`. (The chatbot target predates this
mechanism and still ships dedicated `*_readable` child tags, that pattern works
too, but forces
the target to emit the same information twice and duplicates trajectory
entries when both tags end up in scope.)

**4. Separate knowledge from control.** Put "knows a fact about the victim" on
its own sibling tag so it can be granted without any write power. Both targets
isolate `model_identity` (knowing which LLM is in use) as a sibling of the
control capabilities. That lets you model "the attacker has fingerprinted the
model" independently of "the attacker can change the system prompt", which an
earlier design conflated by putting the model observable at the system root.

**5. Independent channels are independent trees.** If two surfaces do not
subsume each other, they are separate roots in the forest, not parent and child.
The user-input channel and the system-side capabilities are independent, so
`user` is its own root, separate from `system`. You combine them by putting both
in a scope frozenset, never by making one a child of the other.

**6. When the system ingests many data sources, classify them by provenance.**
A tool-using agent reads content from many places with very different trust.
AgentDojo's `tools` tree is a 2x2 grid: *who authored the content* (first party
vs third party) crossed with *who stores it* (first-party vs third-party
storage). This lets a realistic threat model grant only "third-party content in
third-party storage" (the natural prompt-injection surface, e.g. an external
email or a web page) while keeping the user's own first-party data off-limits.

**7. A scope is an antichain.** Never put both a tag and one of its ancestors in
the same `scope`: the ancestor already covers the descendant. The framework's
`distinct_combinations()` enumerates exactly the meaningful antichains for you.
Access level is orthogonal: `scope` and `read_only` can each be an antichain, and
`scope={descendant}, read_only={ancestor}` is the sanctioned way to make only the
descendant's subtree injectable while the rest stays visible.

## Worked example 1: the chatbot target (two trees)

A chatbot has a system side (prompt, model, response) and a user side. The
forest:

```
Tree 1: system
          ├── system_prompt            (controllable: override the prompt)
          │     └── system_prompt_readable   (observable: read the prompt)
          ├── model                    (controllable: rewrite the response)
          │     └── response_readable  (observable: read the response)
          └── model_identity           (observable: which model is in use)
Tree 2: user                           (controllable: send the user message)
```

```python
SYSTEM_TAG               = SecurityDomainTag("system")
SYSTEM_PROMPT_TAG        = SecurityDomainTag("system_prompt", parent=SYSTEM_TAG)
SYSTEM_PROMPT_READABLE_TAG = SecurityDomainTag("system_prompt_readable", parent=SYSTEM_PROMPT_TAG)
MODEL_TAG                = SecurityDomainTag("model", parent=SYSTEM_TAG)
RESPONSE_READABLE_TAG    = SecurityDomainTag("response_readable", parent=MODEL_TAG)
MODEL_IDENTITY_TAG       = SecurityDomainTag("model_identity", parent=SYSTEM_TAG)
USER_TAG                 = SecurityDomainTag("user")   # independent root
```

The scopes this enables read like a catalogue of attackers:

- `{user}` - a blind user: can send messages and see responses, nothing else.
- `{user, response_readable}` - a user who can also read responses out of band.
- `{user, model_identity}` - a user who knows which model they are attacking.
- `{system_prompt_readable, user}` - can see the system prompt but not change it.
- `{system_prompt, user}` - can override the prompt and send messages.
- `{model, user}` - can rewrite the model's responses (a compromised-output
  threat) and send messages.

Each is a precise, separately-runnable threat model, and they exist *because* the
forest separated read from write, knowledge from control, and user from system.

## Worked example 2: the AgentDojo target (three trees)

A tool-calling agent is richer. Three independent roots:

```
Tree 1: system                       (agent-side capabilities the attacker may hold)
          ├── prompt                  (override system prompt)
          ├── tool_catalogue          (full edit of the tool catalogue)
          │     └── tool_catalogue_addable   (register-only: weakest write)
          ├── model_identity
          └── agent_trace             (read the agent's runtime trace)
                ├── agent_trace_messages
                ├── agent_trace_tool_calls
                └── agent_trace_tool_responses
Tree 2: user                         (override the benign user prompt)
Tree 3: tools                        (inject into tool return values)
          ├── content_1p_data_1p     (1st-party content, 1st-party storage)
          ├── content_1p_data_3p     (1st-party content, 3rd-party storage)
          ├── content_3p_data_1p     (3rd-party content, 1st-party storage)
          └── content_3p_data_3p     (3rd-party content, 3rd-party storage)
```

Notice the principles at work:

- **Capability subsumption** in the `tool_catalogue` subtree: scoping to
  `tool_catalogue` grants the weaker register-only capability automatically.
- **Read-only access lives in the scope, not in a tag**: "can see the prompt but
  not change it" is `prompt` under `read_only` rather than `scope`. The
  `agent_trace` tree stays, it is pure observation with no write counterpart,
  a genuine surface of its own.
- **Knowledge isolated** as `model_identity`.
- **A provenance grid** under `tools`. The most realistic prompt-injection
  experiment scopes to `{content_3p_data_3p}` (the attacker controls only the
  content of genuinely external sources, like a received email or a fetched web
  page), which is far weaker, and far more meaningful, than "controls every tool
  output" (`{tools}`).

The full forest is documented in
`superred-modules/targets/agentdojo/src/agentdojo_target/security_tags.py`; its
module docstring is a good template for writing down your own reasoning.

## Choosing the scope

Scope determines the attacker's power, narrow to broad:

- **Narrow** (`{user}`): the most realistic, most common surface. "What can an
  attacker do controlling only the user input?"
- **Medium** (`{content_3p_data_3p}`, `{system_prompt, user}`): a more capable
  or differently-positioned attacker.
- **Read-mostly** (`scope={user}, read_only={system}`): full visibility into
  the system side, but injection only through the user channel.
- **Root** (`{system}`): worst case. The attacker controls everything under that
  tree. Useful for finding any vulnerability at all, less useful as a realistic
  claim.

Always pass a `frozenset`, even for one tag: `scope=frozenset({user_tag})`.

## Per-task scope (advanced)

Usually one Controller runs one fixed scope against every task in the claim. If
different tasks deserve different access (say a claim where each goal targets a
different database table, and you want each task scoped to just its own table),
pass a **resolver** instead of a frozenset. The Controller's `scope` argument
accepts either a `Scope` or a `Callable[[Task], Scope]`, called once per task.
`read_only` accepts the same two forms and is resolved independently, so you can
vary the read-only surface per task too.

```python
from superred.core import ScopeResolver
from my_target import ORDERS_TAG, CUSTOMERS_TAG   # the target's exported tag singletons

def resolve(task) -> frozenset:
    if "customer" in task.goal.description:
        return frozenset({CUSTOMERS_TAG})
    return frozenset({ORDERS_TAG})

controller = Controller(
    optimizer_factory=...,
    target_factory=...,
    security_claim=claim,
    scope=resolve,            # a resolver, not a frozenset
    scope_label="per-table",  # required whenever scope or read_only is a callable
)
```

Two things to get right:

- **`scope_label` is required** whenever `scope` or `read_only` is a resolver (a
  non-empty string) and forbidden when both are fixed scopes. There is no single
  scope to name the run by, so the label names it instead: it becomes the
  persisted filename stem and `ThreatModelResult.scope_label`. Each
  `TaskResult.scope` then records the scope that task actually ran under.
- **Return the target's exported tag singletons**, not freshly built tags.
  Scope matching is by object identity, so import the tags from the target
  module (as above). A new `SecurityDomainTag("orders")` with the same name will
  not match and would gate everything out.

A resolver may raise `NotApplicable`, which contributes an empty set for its own
dimension, exactly like returning `frozenset()`. The task is skipped (it lands
in `skipped_tasks`, like a `configure_target` skip) when the resolved visibility
(`scope | read_only`) is empty: no tag is granted in either dimension. Any tag
(read or write, from either resolver) means the task runs. A resolver raising
any exception *other* than `NotApplicable` fails just that one task
(`stop_reason="error"`) without aborting the rest of the run.

## Tagging components (quick reference)

```python
# Controllable at the user boundary
Controllable(name="chat_message", security_domain=user, description="The user's message")

# Observable at the system level (static context)
Observable(name="model_info", security_domain=system, description="Model identifier")

# Runtime fact at the user level
emit(ObservableEvent(
    observable=Observable(name="model_request", security_domain=user, description="..."),
    content=message,
))

# Config slot (only tasks set this; never the optimizer)
ConfigSpec(name="system_prompt", security_domain=system, description="The system prompt")
```

A trajectory entry tagged `None` is always visible regardless of scope; use that
sparingly, for things that should never be hidden from any attacker.

## Score filtering

A task can report scores at several boundaries. The Controller drops only the
sub-scores whose `security_domain` is out of scope; an untagged sub-score
(`security_domain=None`) is always visible, and the `primary_score` carries no
`security_domain` and is never filtered:

```python
EvaluationResult(
    success=True,
    primary_score=Score(value=0.9),                           # always shown, never scoped
    sub_scores={
        "user_attack": Score(value=0.8, security_domain=user, name="user_attack"),
        "db_leak":     Score(value=0.3, security_domain=db,   name="db_leak"),
    },
)
```

Scoped to `{user}`, the optimizer sees `primary_score` and `user_attack`, but not
`db_leak`.

## Enumerating and sweeping scopes

`SecurityDomain.distinct_combinations()` returns every meaningful antichain
(including the empty set), so you can drive a comprehensive sweep without
hand-listing scopes:

```python
domain = target.security_domain
for scope in domain.distinct_combinations():
    if not scope:                       # skip the empty scope (Controller requires non-empty)
        continue
    controller = Controller(
        optimizer_factory=lambda: MyOptimizer(),
        target_factory=target_factory,
        security_claim=claim,
        scope=scope,                    # a frozenset, passed straight through
        llm_config=attacker_cfg,
        results_dir=f"results/{'_'.join(sorted(t.name for t in scope))}",
    )
    await controller.run()
```

Each `scope` is already the `frozenset` the Controller wants. Building one
Controller per scope is the intended pattern; see
[Running Evaluations](/guide/running-evaluations#sweeping-multiple-threat-models)
for the in-script-loop and one-process-per-cell styles people actually use.
