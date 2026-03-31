# SecurityClaim

Composable, re-iterable collection of tasks.

## Construction

Two factory methods — never mixed:

```python
# From tasks directly
claim = SecurityClaim.from_tasks([task_a, task_b])

# From other claims (lazy chaining)
combined = SecurityClaim.from_claims([claim_1, claim_2])
```

`__init__` raises `TypeError` — must use factory methods.

## Composition model

Claims-of-claims use lazy chaining (`yield from`). No eager flattening. A package exports claims, consumers compose them:

```python
# Package A exports
rag_confidentiality = SecurityClaim.from_tasks([SecretLeakTask(), DocPoisonTask()])
rag_integrity = SecurityClaim.from_tasks([PromptInjectionTask()])

# Consumer composes
full_rag_suite = SecurityClaim.from_claims([rag_confidentiality, rag_integrity])
```

## Design decisions

- **Factory methods over `__init__`**: No runtime isinstance checks needed. Each factory knows its input type.
- **Homogeneous input**: Either all tasks or all claims. Prevents ambiguity.
- **Non-empty**: Both factories require at least one item.
- **Lazy chaining**: `from_claims` stores references, iterates on demand via `yield from`. Efficient for deep composition.
- **Re-iterable**: Tasks are stateless, so iterating a claim multiple times is safe. Standard Python `for task in claim` works repeatedly.
