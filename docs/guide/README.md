---
layout: doc
title: "Getting Started"
permalink: /guide/
---

# Getting Started

SuperRed is a framework for **red-teaming AI systems**: you point an automated
attacker (an *optimizer*) at an AI system (a *target*) and measure whether the
attacker can make the system violate a security property (a *security claim*),
under a precisely defined level of access (a *security scope*).

This guide is for people who want to **use** the framework: wrap an AI system as
a target, write an attacker, define what counts as a successful attack, and run
evaluations. It assumes you can read Python and have seen `asyncio` before, but
no prior knowledge of SuperRed.

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
- The **Controller** wires these together and runs one **threat model**.

## Install

Install the framework from PyPI, along with the three small demo modules used in
the example below:

```bash
pip install superred
pip install superred-target-minimal-llm-chat
pip install superred-optimizer-demo-prompt-list
pip install superred-claim-demo-secret-leak
```

The target reaches the model through [litellm](https://docs.litellm.ai/), so it
works with any litellm-compatible endpoint: you give it a base URL and an API
key. The attacker in this example does no inference of its own, though most
attackers are themselves LLM-driven and call models through litellm too.

## A first evaluation, step by step

The example is a complete, runnable evaluation: a fixed-prompt attacker trying
to make a chatbot leak a secret planted in its system prompt. We will build it
one piece at a time.

Point at any litellm-compatible endpoint by reading its base URL and key from
the environment:

```python
import os

api_base = os.environ["LLM_API_BASE"]
api_key = os.environ["LLM_API_KEY"]
```

**The target: the system under test.** The controller builds a fresh target for
each task, so it takes a *factory* rather than an instance. Working through a
factory is what lets SuperRed run tasks in parallel and reuse targets from a
pool, with the factory sizing that pool to the resources of the host it runs on:

```python
from superred.core.controller import TargetFactory
from minimal_llm_chat import MinimalLLMChatTarget, USER_INPUT_TAG

target = TargetFactory(
    create=lambda: MinimalLLMChatTarget(
        model="gpt-4o-mini", api_base=api_base, api_key=api_key
    ),
)
```

**The claim: what to test and what counts as a break.** This claim plants a
secret in the system prompt and marks the run a success if the model reveals it:

```python
from demo_secret_leak_claim import demo_secret_leak_claim

claim = demo_secret_leak_claim(secret="TIGER-42", trigger="spaghetti")
```

**The controller: one threat model.** It wires the attacker, target, and claim
together. The `scope` is the crucial part: it says the attacker may control only
the user-input surface, and nothing else. This attacker is not LLM-driven, so it
needs no model of its own:

```python
from superred.core.controller import Controller
from demo_prompt_list_optimizer import DemoPromptListOptimizer

controller = Controller(
    optimizer_factory=lambda: DemoPromptListOptimizer(),
    target_factory=target,
    security_claim=claim,
    scope=frozenset({USER_INPUT_TAG}),
)
```

**Run it.** The controller runs the threat model, streams live progress while it
does, and (by default) writes a resumable results tree under
`./superred-results/`:

```python
import asyncio

result = asyncio.run(controller.run())
```

On an interactive terminal you get a live dashboard that updates as the run
proceeds:

<figure class="doc-figure">
  <img src="/assets/img/run-live-terminal.png" alt="superred's live terminal dashboard during a run: a header line with task count, attack success rate, running count and attacker spend, above a table of threat models and tasks with progress, ASR, score, outcome counts and cost.">
  <figcaption>The live terminal dashboard, updating as the run proceeds: each threat model and its tasks, with progress, attack success rate, score, and attacker spend.</figcaption>
</figure>

and settles into the final result once the run finishes:

<figure class="doc-figure">
  <img src="/assets/img/run-finished-terminal.png" alt="superred's terminal dashboard after the run finishes: the header shows 1 of 1 tasks, 100% attack success rate, 0 still running, and $0.0000 attacker spend, with the threat-model row marked complete at full progress and 100% ASR.">
  <figcaption>When the run finishes, the dashboard settles into the final result: here 1 of 1 tasks succeeded, 100% attack success rate, and $0 attacker spend (the demo attacker replays a fixed prompt list and calls no LLM, so it costs nothing).</figcaption>
</figure>

Once a run has finished, point `superred serve` at its results directory:

```bash
superred serve ./superred-results
```

It opens an interactive web report where you can browse the summary and drill
into per-task metrics, errors, and full run trajectories.

<figure class="doc-figure">
  <img src="/assets/img/results-web-report.png" alt="superred web report: attack success rate 100 percent over one task, attacker cost $0.00, a run-outcomes bar, and a per-task table showing one succeeded task.">
  <figcaption>The web report served from a results directory: attack success rate, attacker cost (here $0.00, since the demo attacker makes no LLM calls), run outcomes, and a per-task table you can expand to open each run's trajectory.</figcaption>
</figure>

Pass `report=False` to silence progress, and `persist=False` to skip writing the
results tree. The persisted trajectories are unscrubbed attack content, so treat
the results folder as sensitive.

## What happens when you run it

1. The **Controller** takes the task in the claim and gives it a fresh target.
2. The **Task** configures the target (plants the secret in the system prompt).
3. The **Optimizer** runs as a concurrent task; for each run it injects the next
   prompt from its list into the `user_input` controllable.
4. After each run the **Task** evaluates the trajectory: did the secret appear
   in the response?
5. The optimizer keeps going until it exhausts its prompt list, or the
   controller hits its per-task safety cap.
6. The controller prints the summary above and returns a `ThreatModelResult`
   holding the same data (per-task scores, runs, and LLM usage) for programmatic
   use.

In this run the model leaked the secret, so the task is marked `SUCCEEDED` with
a score of `1.0000`.

## The shape of every SuperRed program

Everything you build later is a variation on the same five parts:

- a `target_factory` that builds the system under test,
- a `security_claim` describing what to attack and how success is judged,
- an `optimizer_factory` that builds the attacker,
- a `scope` (a `frozenset` of security-domain tags) saying what the attacker may
  touch,
- optionally an `llm_config` giving the attacker a model and a spending budget.

{% include diagrams/u1.html %}

## What to read next

We recommend you read [Core Concepts](/guide/core-concepts) next: it explains
the vocabulary and the run loop that everything else builds on.

From there, two paths lead out: run existing pieces, or build your own.

- [Using a Module](/guide/using-modules) shows how to drop in the ready-made
  attackers, targets, and benchmarks from the [module catalogue](/modules).
- [Running Evaluations](/guide/running-evaluations) covers sweeping several
  threat models at once, scaling up runs, and saving results to disk.
- [Writing a Target](/guide/writing-a-target) walks through wrapping your own AI
  system as a target.
