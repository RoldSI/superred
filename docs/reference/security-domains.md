---
layout: doc
title: "Security Domains"
permalink: /reference/security-domains
---

# Security Domains

A **security domain** is a trust boundary: a labelled surface of the target that
an attacker either controls (and can observe) or does not. Security domains are
how superred expresses a **threat model**. The target defines them; the
Controller filters by them.

This page specifies the types and their exact semantics. For the modelling
question, how to map a real system's trust structure onto domains, see the guide
page [Security Domains](/guide/security-domains), which works through the shipped
targets. This reference and that guide use the same model; this one is the
precise contract.

## The two-level model

There are two types, and the distinction matters:

- **`SecurityDomainTag`** a single node in a tree. This is the runtime object you
  attach to a controllable, an observable, a config slot, or a score.
- **`SecurityDomain`** a validated, immutable **forest** (one or more trees) of
  tags. A target returns one from its `security_domain` property. It exists to
  validate the tree and to enumerate scopes.

Tags are defined **at runtime**, not as an enum: each target creates its own tag
objects. Scope matching, everywhere in the framework, is by **object identity**,
so the tag instances a target exports are the canonical ones; a freshly built tag
with the same name is a different tag.

## `SecurityDomainTag`

A frozen dataclass with two fields:

- `name: str` a human-readable identifier.
- `parent: SecurityDomainTag | None = None` the parent tag, or `None` for a root.

You build a tree by pointing children at parents:

```python
from superred.core import SecurityDomainTag

system   = SecurityDomainTag("system")
external = SecurityDomainTag("external", parent=system)
user     = SecurityDomainTag("user", parent=external)
api      = SecurityDomainTag("api", parent=external)   # sibling of user
```

### `tag.includes(other)`

The one relationship that matters. `tag.includes(other)` is `True` when `other`
is `tag` itself or any descendant of it. It is implemented by walking from
`other` up the parent chain, comparing by **identity** (`is`), until it reaches
`tag` or runs off the top.

```python
system.includes(user)     # True  - ancestor includes descendant
external.includes(api)    # True
user.includes(user)       # True  - a tag includes itself
external.includes(system) # False - a descendant does not include its ancestor
```

The meaning: **holding a tag grants everything beneath it.** If an attacker
controls `system`, it controls `external`, `user`, and `api` too. This is what
makes a coarse scope a superset of a finer one.

## `SecurityDomain`

A `SecurityDomain` wraps a flat list of tags and validates them into a forest.
Construction raises `ValueError` if:

- two tags share a `name` (names must be unique within a domain), or
- a tag's `parent` is not itself in the list (no orphan references).

```python
from superred.core import SecurityDomain

domain = SecurityDomain([system, external, user, api])   # validates the forest
```

The object is immutable after construction (its `__setattr__` and `__delattr__`
raise). It exposes:

- `roots` the tags with no parent (the tops of the trees).
- `distinct_combinations()` all the scopes worth testing (below).

### `distinct_combinations()`

Returns every **distinct combination of tags worth evaluating**, as a
`list[frozenset[SecurityDomainTag]]` (that is, a list of `Scope`s).

The rule is that a combination never contains both a tag and one of its
ancestors, because the ancestor already covers the descendant. Such a set is
called an **antichain**. Within one tree the method enumerates the antichains;
across independent trees it takes the Cartesian product of each tree's
selections. The empty set is included.

```python
for scope in domain.distinct_combinations():
    if not scope:            # the Controller requires a non-empty scope
        continue
    ...                       # one meaningful threat model per scope
```

This is how you drive a comprehensive sweep without hand-listing scopes: every
element is exactly a `frozenset` the Controller accepts.

## `Scope` and `scope_includes` {#scope-and-scope_includes}

A **scope** is a set of tags, defining a multi-tag attack surface:

```python
Scope = frozenset[SecurityDomainTag]
```

A surface is "in scope" if **any** tag in the set includes it:

```python
def scope_includes(scope: Scope, tag: SecurityDomainTag) -> bool:
    return any(s.includes(tag) for s in scope)
```

So scoping to `{external}` covers `external`, `user`, and `api` at once; scoping
to `{root}` covers everything under that root; an empty scope covers nothing.
Caller-specified scopes are conventionally antichains, but this is neither
enforced nor required, `scope_includes` behaves correctly either way.

Always pass a `frozenset`, even for a single tag: `scope=frozenset({user})`.

## Access levels: `scope` versus `read_only`

Access level, whether the attacker can only **read** a surface or can also
**write** (inject into) it, is **not** a property of a tag. It is expressed by
which of the Controller's two scope sets a tag lands in:

- **`scope`** the read & write surface: visible **and** injectable.
- **`read_only`** an optional second set: visible **but not** injectable.

`read_only` defaults to empty, so by default the whole `scope` is read & write,
the classic behavior. To make part of the surface read-only, list it under
`read_only` instead of `scope`.

{% include diagrams/d3.html %}

```python
# See the whole system subtree, but inject only into the prompt:
Controller(
    scope=frozenset({prompt_tag}),      # read & write
    read_only=frozenset({system_tag}),  # visible only
    ...,
)
```

Two rules govern the relationship:

- **Read & write overrules read-only.** Only `scope` drives the injection
  decision. A `read_only` tag that is already covered by `scope` has no effect
  (it stays injectable). The useful pattern is the reverse: a read & write tag
  **inside** a read-only ancestor's subtree, as above, makes just that subtree
  injectable while the rest of the tree stays visible.
- **They cannot both be empty.** At least one tag must be granted in one of the
  two sets.

Internally the Controller derives two scopes from these arguments:

- the **write scope** (= `scope`), which drives the one injection check;
- the **visibility scope** (= `scope | read_only`), which drives everything else.

When `read_only` is empty the two are identical.

## The five filtered surfaces

Scope is enforced across **every** channel between the optimizer and the target.
For a given `(scope, read_only)`:

| Surface | Filter | Basis |
|---------|--------|-------|
| **Controllables** passed to `initialize()` | only the injectable ones | write scope |
| **Observables** passed to `initialize()` | in-scope observables, **plus** any read-only controllable re-presented as an observable (with `content=None`) | visibility scope |
| **Controllable events** during a run | out-of-scope, and read-only, events are auto-answered `ControllableNoInjection` | write scope |
| **Trajectory** the optimizer reads | a `FilteredTrajectory` of in-scope items | visibility scope |
| **Feedback sub-scores** | tagged out-of-scope sub-scores are dropped; untagged ones stay | visibility scope |

A read-only controllable is therefore honest by construction: at `initialize()`
it appears in the optimizer's **observables**, not its controllables, because for
this threat model it is a thing you read, not a thing you inject. Its runtime
values still arrive on the trajectory as its (declined) controllable events. The
`primary_score`, `success`, and `rationale` are always delivered regardless of
scope, because the attacker needs the main optimization signal. This filtering
mechanism is implemented in the [Controller](/reference/controller#security-domain-filtering)
via the [`security_domain_filter` middleware](/reference/events-and-trajectory#middleware-where-scope-and-recording-live).

## Per-task scopes: `ScopeResolver`

Usually one Controller applies one fixed scope to every task in the claim.
Sometimes different tasks deserve different access (a claim where each goal
targets a different database table, and you want each task scoped to just its
table). For that, the Controller's `scope` and `read_only` arguments each accept,
in place of a fixed `Scope`, a **resolver**:

```python
ScopeResolver = Callable[[Task], Scope]
```

The Controller calls it **once per task** to compute that task's scope.
`callable(...)` is the discriminator between the fixed and dynamic forms, and the
two arguments are resolved independently of each other.

```python
from superred.core import ScopeResolver
from my_target import ORDERS_TAG, CUSTOMERS_TAG   # the target's exported singletons

def resolve(task) -> frozenset:
    if "customer" in task.goal.description:
        return frozenset({CUSTOMERS_TAG})
    return frozenset({ORDERS_TAG})

controller = Controller(
    optimizer_factory=..., target_factory=..., security_claim=claim,
    scope=resolve,             # a resolver, not a frozenset
    scope_label="per-table",   # required whenever scope or read_only is a resolver
)
```

Four things to get right:

- **`scope_label` is required in dynamic mode.** When either argument is a
  resolver, `scope_label` must be a non-empty string (there is no single concrete
  scope to name the run by); it feeds the persisted run's identity and lands on
  `ThreatModelResult.scope_label`. When both are fixed frozensets, `scope_label`
  must be `None`. Violating either raises `ValueError` at construction.
- **A resolver may skip a task.** Raising `NotApplicable` from a resolver
  contributes an empty set for its own dimension, exactly like returning
  `frozenset()`. The task is **skipped** (it lands in `skipped_tasks`, the same
  channel as a `configure_target` skip) only when the resolved **visibility**
  (`scope | read_only`) is empty, that is, no tag was granted in either
  dimension. Any tag in either dimension means the task runs.
- **A resolver failure is contained.** A resolver raising any other exception
  fails just that one task (`stop_reason="error"`) and leaves the rest of the run
  going.
- **Return the target's exported singletons.** Because matching is by identity,
  the resolver must return the same tag objects the target exposes (import them
  from the target module). A new `SecurityDomainTag("orders")` with the same name
  will not match and would gate everything out.

Each task then records the scope it actually ran under on `TaskResult.scope` and
`TaskResult.read_only`. See the [Controller](/reference/controller#scope-may-be-a-fixed-scope-or-a-per-task-scoperesolver)
for how this threads through construction, and
[Results & Persistence](/reference/results) for where it is recorded.
