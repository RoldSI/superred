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

system.includes(user)     # True: ancestor includes descendant
external.includes(api)    # True
external.includes(system) # False: descendant does not include ancestor
external.includes(user)   # True
user.includes(user)       # True: a tag includes itself
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
make B a child of A. In AgentDojo, `tool_catalogue` is the parent write
capability, and holding it automatically grants its three children
`tool_catalogue_add`, `tool_catalogue_edit`, and `tool_catalogue_remove`.
Granting the parent in a scope grants the weaker capabilities under it.

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

**6. When the system ingests many data sources, give each store its own leaf.**
A tool-using agent reads from and writes to many stores of very different trust.
Model the tool surface as a forest that mirrors the real systems: a grouping
`tools` root, a node per service (AgentDojo has `banking`, `workspace`, `slack`,
`travel`), and under each one leaf per separately-compromisable data store
(`workspace_inbox`, `banking_bank_account`, and so on). Reading from a store and
the agent action that mutates it share that store's leaf, so granting a service
covers both. A realistic threat model can then grant just the store an external
source actually reaches (say `workspace_inbox` for a poisoned email) while the
rest stays off-limits.

**7. A scope is an antichain.** Never put both a tag and one of its ancestors in
the same `scope`: the ancestor already covers the descendant. The framework's
`distinct_combinations()` enumerates exactly the meaningful antichains for you.
Access level is orthogonal: `scope` and `read_only` can each be an antichain, and
`scope={descendant}, read_only={ancestor}` is the sanctioned way to make only the
descendant's subtree injectable while the rest stays visible.

## Worked example 1: a chatbot (two trees)

A chatbot has a system side (prompt, model, response) and a user side. Modelled
the way principle 3 recommends, one tag per surface with read-only expressed
through `read_only` rather than separate readable tags:

```
Tree 1: system
          ├── system_prompt     (override the system prompt, or read only)
          ├── model             (rewrite the model's responses, or read only)
          └── model_identity    (which model is in use: observe only)
Tree 2: user                    (send the user message)
```

```python
SYSTEM_TAG         = SecurityDomainTag("system")
SYSTEM_PROMPT_TAG  = SecurityDomainTag("system_prompt", parent=SYSTEM_TAG)
MODEL_TAG          = SecurityDomainTag("model", parent=SYSTEM_TAG)
MODEL_IDENTITY_TAG = SecurityDomainTag("model_identity", parent=SYSTEM_TAG)
USER_TAG           = SecurityDomainTag("user")   # independent root
```

Seeing a surface versus changing it is a `read_only` decision, so there are no
separate readable tags. The scopes read like a catalogue of attackers:

- `scope={user}`: a blind user who can send messages and see the reply, nothing
  else.
- `scope={user, model_identity}`: also knows which model it is attacking.
- `scope={user}`, `read_only={system_prompt}`: can see the system prompt but not
  change it.
- `scope={user, system_prompt}`: can override the system prompt and send messages.
- `scope={user}`, `read_only={model}`: can read the model's responses out of band,
  but not rewrite them.
- `scope={user, model}`: can rewrite the model's responses (a compromised-output
  threat) and send messages.

{% include diagrams/u6.html %}

Each is a precise, separately-runnable threat model, and they exist because the
forest separates the surfaces (knowledge from control, user from system) while
`read_only` separates seeing a surface from changing it. The shipped `chatbot`
module predates `read_only` and still ships dedicated `*_readable` subtags for
these read-only variants (principle 3); the design above is how it would be
modelled today.

## Worked example 2: the AgentDojo target (three trees)

A tool-calling agent is richer. Three independent roots:

```
Tree 1: system
          ├── system_prompt
          ├── tool_catalogue                 (add / edit / remove below)
          │     ├── tool_catalogue_add
          │     ├── tool_catalogue_edit
          │     └── tool_catalogue_remove
          ├── model_identity
          ├── detailed_system_specification  (a leaked spec of the system)
          └── agent_trace
                └── agent_trace_messages
Tree 2: user
Tree 3: tools
          ├── banking
          │     ├── banking_bank_account
          │     ├── banking_filesystem
          │     └── banking_user_account
          ├── workspace
          │     ├── workspace_inbox
          │     ├── workspace_calendar
          │     └── workspace_cloud_drive
          ├── slack
          │     ├── slack_slack
          │     └── slack_web
          └── travel                         (hotels, flights, inbox, +5 more stores)
```

Notice the principles at work:

- **Capability subsumption** in the `tool_catalogue` subtree: scoping to
  `tool_catalogue` grants the weaker add, edit, and remove capabilities
  automatically.
- **Read-only lives in the scope, not in a tag**: "list the tool catalogue but
  not change it" is `tool_catalogue` under `read_only`, and "see the system
  prompt but not override it" is `system_prompt` under `read_only`.
- **Knowledge isolated** as read-only surfaces of their own: `model_identity`,
  and `detailed_system_specification` for an attacker who has obtained a design
  leak of the system.
- **One leaf per data store** under `tools`, grouped by service. The most
  realistic prompt-injection experiment scopes to a single store an external
  source can reach, like `{workspace_inbox}` (a poisoned email) or `{slack_web}`
  (a fetched web page), far weaker, and far more meaningful, than "controls
  every tool output" (`{tools}`). Reading a store and the agent action that
  mutates it share the store's leaf, so granting a service covers both.

The full forest is documented in
[`agentdojo_target/security_tags.py`](https://github.com/RoldSI/superred-modules/blob/main/targets/agentdojo/src/agentdojo_target/security_tags.py);
its module docstring is a good template for writing down your own reasoning.

## Choosing the scope

Scope determines the attacker's power, narrow to broad:

- **Narrow** (`{user}`): the most realistic, most common surface. "What can an
  attacker do controlling only the user input?"
- **Medium** (`{workspace_inbox}`, `{system_prompt, user}`): a more capable
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
  scope to name the run by, so the label names it instead: it feeds the
  persisted experiment's measurement identity (its `{hash8}` folder suffix and
  recorded parameters) and `ThreatModelResult.scope_label`. Each
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
from superred.core.controller import run_all

domain = target.security_domain
controllers = [
    Controller(
        optimizer_factory=lambda: MyOptimizer(),
        target_factory=target_factory,
        security_claim=claim,
        scope=scope,                    # a frozenset, passed straight through
        llm_config=attacker_cfg,
        results_dir="results",          # one shared folder; a subfolder per scope
    )
    for scope in domain.distinct_combinations()
    if scope                            # skip the empty scope (Controller requires non-empty)
]
results = await run_all(controllers, concurrency=4)   # one shared live dashboard
```

Each `scope` is already the `frozenset` the Controller wants, and `run_all` drives
the whole sweep on one shared live dashboard, returning the results in input
order. See [Running Evaluations](/guide/running-evaluations#sweeping-multiple-threat-models).
