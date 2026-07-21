---
layout: doc
title: "SecurityClaim"
permalink: /reference/security-claim
---

# SecurityClaim

A **security claim** is a composable, re-iterable collection of
[tasks](/reference/task). It is what you hand to the
[Controller](/reference/controller): the set of adversarial objectives to evaluate.
Conceptually it represents a property claimed to hold on a target (confidentiality,
integrity, and so on) that the optimizer may disprove, one task at a time.

`SecurityClaim` is generic over the target type (`SecurityClaim[T_Target]`, bound
to `Target`), so a claim's tasks all target the same kind of system.

## Construction

Build a claim through one of two factory classmethods, never by calling the
constructor (`__init__` raises `TypeError`). A claim is built from **either** tasks
**or** other claims, not a mix, and each factory requires at least one item (else
`ValueError`).

```python
from superred.core import SecurityClaim

# From tasks directly:
claim = SecurityClaim.from_tasks([task_a, task_b])

# From other claims (composed):
combined = SecurityClaim.from_claims([claim_1, claim_2])
```

In practice you rarely list tasks by hand: a benchmark module ships a **factory
function** (for example `harmbench_claim(...)`) that loads a dataset and produces
one task per prompt.

## Composition model

`from_claims` composes **lazily**: it stores references to the sub-claims and
iterates them on demand with `yield from` (Python's `iter`/`__iter__` protocol).
There is no eager flattening, so deep composition (claims of claims of claims)
stays cheap. A package can export small claims and let a consumer compose them:

```python
# A package exports focused claims:
rag_confidentiality = SecurityClaim.from_tasks([SecretLeakTask(), DocPoisonTask()])
rag_integrity       = SecurityClaim.from_tasks([PromptInjectionTask()])

# A consumer composes them into a suite:
full_rag_suite = SecurityClaim.from_claims([rag_confidentiality, rag_integrity])
```

## Re-iterability

A claim can be iterated **repeatedly**:

```python
for task in claim:
    ...
for task in claim:   # works again
    ...
```

This is safe precisely because [tasks are stateless](/reference/task#stateless-design):
iterating a claim never mutates its tasks, so the Controller (and your own analysis
code) can walk it more than once.

## Design decisions

- **Factory methods over `__init__`.** Each factory knows its input type, so no
  runtime `isinstance` checks are needed and construction cannot be ambiguous.
- **Homogeneous input.** A claim is all tasks or all claims, never mixed, which
  keeps composition unambiguous.
- **Non-empty.** Both factories require at least one item; an empty claim is a
  mistake, not a valid state.
- **Lazy chaining.** `from_claims` iterates on demand, so composing large claims
  out of small ones has no upfront cost.
- **Re-iterable.** Stateless tasks make a claim a safe, ordinary Python iterable
  you can loop over as often as you like.
