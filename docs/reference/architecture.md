---
layout: doc
title: "Architecture Overview"
permalink: /reference/
---

# Architecture Overview

superred is a framework for **red-teaming AI systems**: pointing an automated
attacker at an AI system and measuring, under a precisely defined level of
access, whether the attacker can make the system misbehave.

This page is the map. It defines the pieces once, shows how they fit together,
and points to the page that specifies each one in full. Every reference page is
written to be read on its own, so you can also jump straight to the component you
care about.

## The five roles

An evaluation is built from five kinds of object. Three are things you write and
ship as separate packages; two are framework machinery you configure but do not
subclass.

| Role | What it is | You |
|------|-----------|-----|
| **[Target](/reference/target)** | The AI system under test (a chatbot, a tool-using agent) | implement |
| **[Optimizer](/reference/optimizer)** | The attacker: an automated strategy that tries to break the target | implement |
| **[Task](/reference/task)** | One adversarial objective: set the target up, then judge the outcome | implement |
| **[SecurityClaim](/reference/security-claim)** | A re-iterable collection of tasks (a test suite) | implement |
| **[Controller](/reference/controller)** | The orchestrator: runs one claim under one threat model | configure |

The Target is a **passive** attack surface and the Task **judges** the outcome.
The Optimizer is the only actively adversarial component. It never touches the
target directly; it acts and observes only through the events the Controller
routes between them.

## The central idea: one Controller is one threat model

A **threat model** is the answer to "what can the attacker do?". superred pins it
down with two settings, both fixed when you construct the Controller:

- a **[security-domain scope](/reference/security-domains)**: which trust
  boundaries of the target the attacker controls and can observe;
- an **`llm_config`** (and cost cap): which model the attacker may call, and how
  much it may spend.

One `Controller` evaluates one `SecurityClaim` under one `(scope, llm_config)`
combination and returns one
[`ThreatModelResult`](/reference/results#threatmodelresult). Comparing several
threat models (a weak attacker against a strong one, with feedback against
without) is the caller's job: build several Controllers and run them, optionally
sharing one live dashboard through
[`run_all`](/reference/controller#sweeping-multiple-threat-models). This keeps
each measurement a single, self-contained, reproducible unit.

## The event-driven loop

The Target and the Optimizer never call each other. They run as two independent
concurrent tasks and communicate only through typed **events** that pass through
the Controller. The Controller sits in the middle: it filters events to the
scope, records everything onto a **trajectory**, and bridges the two sides.

{% include diagrams/d1.html %}

One **run** is one full pass of the target plus its evaluation, and it unfolds
like this:

1. The Controller sends a `RunStartEvent` to the optimizer.
2. `target.run()` executes. The target **emits** one-way `ObservableEvent`s to
   record what it does, and **pauses** at each injection point by sending a
   `ControllablePreCallEvent` (and optionally a `ControllablePostCallEvent`)
   through the channel. The optimizer answers each one with a value to inject
   (`ControllableInjection`) or a decline (`ControllableNoInjection`).
3. The Controller runs `task.evaluate()` to score the run.
4. The Controller sends a `RunEndEvent` carrying that evaluation. The optimizer
   answers with `RunEndResponse(done=...)` to stop or to try again.

A task can take many runs: the attacker keeps trying until it declares itself
done, exhausts its budget, or hits the Controller's `max_runs_per_task` cap. The
full mechanism, the channel, the trajectory, and the exact event contract, is
specified in
[Events, Channel & Trajectory](/reference/events-and-trajectory).

## Scope: the same events, filtered to a boundary

The Target exposes every attack surface it has, always. The **threat model** is
imposed entirely by the Controller, by filtering. When you scope a Controller to
a set of security-domain tags, the Controller constrains **every** channel
between the optimizer and the target to that boundary:

- only in-scope **controllables** are offered as injection points;
- only in-scope **observables** are shown;
- the optimizer's **trajectory view** contains only in-scope entries;
- out-of-scope **controllable events** are auto-declined without asking;
- out-of-scope evaluation **sub-scores** are hidden.

This is what lets a single target answer many precise questions ("what can an
attacker do controlling only the user message?") without rewriting it. Access
level is a property of the scope, not of the tag: a tag can be **read & write**
(in `scope`) or **read-only** (in the separate `read_only` set). The exact
semantics live in [Security Domains](/reference/security-domains).

## What comes out

`controller.run()` returns a `ThreatModelResult` and, by default, writes a
structured, resumable **results tree** to disk. A run streams live progress to a
terminal dashboard while it is in flight, and the bundled `superred serve`
command opens a web report over the results afterward. The result objects, the
on-disk layout, the resume behavior, the reader API, and the reporting are all
specified in [Results & Persistence](/reference/results).

## Map of this reference

**Interfaces you implement or drive:**

- **[Controller](/reference/controller)** the orchestrator: construction, the run
  loop, scope filtering, budget enforcement, sweeping.
- **[Optimizer](/reference/optimizer)** the attacker interface: the actor model,
  `on_event`, consumption models, trajectory access.
- **[Target](/reference/target)** the system-under-test interface: config and
  query surfaces, controllables and observables, the run method, the state
  lifecycle.
- **[Task](/reference/task)** one adversarial objective: generics, statelessness,
  configure and evaluate.
- **[SecurityClaim](/reference/security-claim)** composable, re-iterable
  collections of tasks.

**The mechanisms that connect them:**

- **[Events, Channel & Trajectory](/reference/events-and-trajectory)** the
  communication substrate: the event hierarchy, the bidirectional channel, the
  trajectory and its filtered view, and the middleware that enforces scope.
- **[Security Domains](/reference/security-domains)** the trust-boundary model:
  tags, the forest, scopes, read-only access, and per-task resolvers.

**The data:**

- **[Core Types](/reference/types)** the plain value objects: goals, config and
  query specs, controllables, observables, scores, and LLM types.
- **[Results & Persistence](/reference/results)** what a run produces: result
  objects, the on-disk tree, resume, the reader API, live reporting, and the
  `superred serve` web report.

**Change history:**

- **[Migration](/reference/migration)** per-version migration notes.

## Design commitments

A few decisions recur throughout the framework. They are stated here once and
justified on the relevant pages.

- **Event-driven, not call-driven.** Target and optimizer are decoupled by an
  `EventChannel`; each is a concurrent task with its own pace. Lifecycle points
  (`RunStartEvent`, `RunEndEvent`) are ordinary events, not special hooks.
- **The trajectory is the single event log.** There is no separate log. Every
  event and response is recorded onto the trajectory as it happens, and the
  optimizer reads a scope-filtered view of it.
- **Scope is enforced by the Controller, invisibly to the modules.** A target
  always exposes its full surface; an optimizer always makes strongest use of
  whatever it is given. Neither knows what the current threat model hides.
- **Fresh instances per task.** Each task gets a new target and a new optimizer,
  so concurrent tasks never share mutable state.
- **Immutable value types.** Events, specs, scores, tags, and configs are frozen
  dataclasses. Security-domain tags are runtime-defined objects, not an enum, so
  each target declares its own.
- **Thread-safe at every boundary.** The trajectory, the channel, the envelope,
  and the LLM client are all safe to touch from multiple threads, so a target
  may bridge blocking work (Docker, subprocesses) back to the event loop.

## The asyncio runtime

There is one event loop, on one thread, and the **caller** provides it:

```python
result = asyncio.run(controller.run())
```

The Controller never creates its own loop, so it embeds cleanly in larger async
applications (web servers, notebooks, pipelines). The target and optimizer run
as two `asyncio.Task`s on that loop; a target with internal parallelism may spawn
more. The concurrency model is detailed in
[Events, Channel & Trajectory](/reference/events-and-trajectory#concurrency-model).

## Where things live in the source

```
src/superred/
  cli.py                 -- the `superred` command (serve a results dir)
  core/
    controller.py        -- Controller, TargetFactory, run_all, result types
    channel.py           -- EventChannel, EventEnvelope
    middleware.py        -- Middleware, compose, security_domain_filter,
                            trajectory_recorder
    llm.py               -- LLMClient (the constrained LLM proxy)
    persistence.py       -- results-tree writers, resume engine, reader API
    reporting.py         -- ProgressReporter, the live dashboard, plain output
    interfaces/
      optimizer.py       -- Optimizer ABC
      target.py          -- Target ABC
      task.py            -- Task[T_Target] ABC, NotApplicable
      security_claim.py  -- SecurityClaim
    types/
      goal.py            -- Goal
      state.py           -- ConfigSpec, QuerySpec, QueryParam
      controllable.py    -- Controllable
      observable.py      -- Observable, ObservableValue
      event.py           -- Event, EventResponse, callback aliases
      events.py          -- the concrete events and responses
      trajectory.py      -- Trajectory, FilteredTrajectory, get_domain
      evaluation.py      -- Score, EvaluationResult
      security_domain.py -- SecurityDomainTag, SecurityDomain, Scope
      llm.py             -- LLMConfig, LLMUsage, BudgetExhaustedError
```

Everything public is re-exported from `superred.core` (and the value types from
`superred.core.types`), so `from superred.core import Controller, Scope, ...`
is the intended import path.
