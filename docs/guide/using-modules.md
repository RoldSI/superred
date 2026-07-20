---
layout: doc
title: "Using a Module"
permalink: /guide/using-modules
---

# Using a Module

Provided modules are ordinary Python packages. To use one: `pip install` it,
import its class or factory, and pass it to the [Controller](/reference/controller).
The pattern is the same
for all three kinds, shown below.

## Using an optimizer

An optimizer is the attacker. Install it, import the class, and give the
controller a factory that builds a fresh one per task:

```bash
pip install pair-optimizer
```

```python
from pair_optimizer import PAIROptimizer

controller = Controller(
    optimizer_factory=lambda: PAIROptimizer(),
    ...
)
```

Any options an attack accepts (number of streams, iterations, and so on) are
passed at construction, inside the lambda. For example, PAIR takes its stream
and iteration counts as constructor arguments:

```python
controller = Controller(
    optimizer_factory=lambda: PAIROptimizer(n_streams=3, n_iterations=5),
    ...
)
```

The controller never shares an optimizer between tasks.

## Using a target

A target is the system under test. Install it, import it, and wrap it in a
`TargetFactory`:

```bash
pip install chatbot-target
```

```python
from chatbot_target import ChatbotTarget, USER_TAG

target_factory = TargetFactory(
    create=lambda: ChatbotTarget(model="gpt-4o-mini", api_key=key),
)
```

Each target exports the security-domain tags it defines (here `USER_TAG`). You
use those tags to build the `scope` that says what the attacker may control.

## Using a security claim

A security claim defines what to test and what counts as a break. Install it,
import its factory, and pass the result to the controller:

```bash
pip install secclaim-harmbench
```

```python
from secclaim_harmbench import harmbench_claim

controller = Controller(
    security_claim=harmbench_claim(),
    ...
)
```

Claim factories take options such as which split to run or which judge model to
use. See each package for the specifics, and [Running Evaluations](/guide/running-evaluations)
for how the controller turns a claim into a full run.
