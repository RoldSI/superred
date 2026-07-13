---
layout: doc
title: "Getting Started"
permalink: /guide/
---

# Getting Started

SuperRed is a framework for **red-teaming AI systems**: you point an automated
attacker (an *optimizer*) at an AI system (a *target*) and measure whether the
attacker can make the system do something it should not, under a precisely
defined level of access (a *security scope*).

This guide is for people who want to **use** the framework: wrap an AI system as
a target, write an attacker, define what counts as a successful attack, and run
evaluations. It assumes you can read Python and have seen `asyncio` before, but
no prior knowledge of SuperRed. For the internal design rationale, see the
[Reference](/reference/).

## The mental model

Five pieces fit together, and the fastest way to understand them is to see them
in one short program:

- A **Target** is the AI system under test. It exposes labelled **injection
  points** (controllables) and **readable facts** (observables), each tagged
  with a **security domain** (a trust boundary).
- A **SecurityClaim** is a bundle of **Tasks**. A task sets the target up and
  later judges whether the attack worked.
- An **Optimizer** is the attacker: it receives events as the target runs and
  decides what to inject.
- The **Controller** wires these together and runs one **threat model**: one
  security scope, one attacker budget, against one claim.

## Install

Install the framework from PyPI, plus the three small demo modules used in the
example below (they ship in the `superred-modules` repository):

```bash
pip install superred
pip install -e ./superred-modules/targets/test_basic_llm_chat
pip install -e ./superred-modules/optimizers/test_basic_prompt_list
pip install -e ./superred-modules/security_claims/test_basic_secret_leak
```

The target calls a real LLM through [litellm](https://docs.litellm.ai/), so set
an API key for any litellm-compatible endpoint. The attacker in this example
does no LLM calls of its own.

## A first evaluation, step by step

The example is a complete, runnable evaluation: a fixed-prompt attacker trying
to make a chatbot leak a secret planted in its system prompt. We will build it
one piece at a time.

Start with the imports and read your API key from the environment:

```python
import asyncio
import os

from superred.core.controller import Controller, TargetFactory
from basic_llm_chat_target import BasicLLMChatTarget, USER_INPUT_TAG
from basic_prompt_list_optimizer import BasicPromptListOptimizer
from basic_secret_leak_claim import basic_secret_leak_claim

key = os.environ["OPENAI_API_KEY"]
```

**The target: the system under test.** The controller builds a fresh target for
each task, so it takes a *factory* rather than an instance:

```python
target = TargetFactory(
    create=lambda: BasicLLMChatTarget(model="gpt-4o-mini", api_key=key),
)
```

**The claim: what to test and what counts as a break.** This claim plants a
secret in the system prompt and marks the run a success if the model reveals it:

```python
claim = basic_secret_leak_claim(secret="TIGER-42", trigger="spaghetti")
```

**The controller: one threat model.** It wires the attacker, target, and claim
together. The `scope` is the crucial part: it says the attacker may control only
the user-input surface, and nothing else. This attacker is not LLM-driven, so it
needs no model of its own:

```python
controller = Controller(
    optimizer_factory=lambda: BasicPromptListOptimizer(),
    target_factory=target,
    security_claim=claim,
    scope=frozenset({USER_INPUT_TAG}),
)
```

**Run it and inspect the result:**

```python
result = asyncio.run(controller.run())

for task in result.task_results:
    print(f"{task.task.goal.description}: success={task.success}")
```

## What happens when you run it

1. The **Controller** takes the task in the claim and gives it a fresh target.
2. The **Task** configures the target (plants the secret in the system prompt).
3. The **Optimizer** runs as a concurrent task; for each run it injects the next
   prompt from its list into the `user_input` controllable.
4. After each run the **Task** evaluates the trajectory: did the secret appear
   in the response?
5. The optimizer keeps going until it exhausts its prompt list, or the
   controller hits its per-task safety cap.
6. The controller returns a `ThreatModelResult` you can inspect.

If the model leaked the secret, `task.success` is `True`.

## The shape of every SuperRed program

Everything you build later is a variation on the same five parts:

- a `TargetFactory` that builds the system under test,
- a `SecurityClaim` describing what to attack and how success is judged,
- an `optimizer_factory` that builds the attacker,
- a `scope` (a `frozenset` of security-domain tags) saying what the attacker may
  touch,
- optionally an `LLMConfig` giving the attacker a model and a spending budget.

## What to read next

- [Core Concepts](/guide/core-concepts) for the vocabulary and the run loop.
- [Writing a Target](/guide/writing-a-target) to wrap your own system.
- [Security Domains](/guide/security-domains) for the most important design
  decision you will make: how to model trust boundaries.
