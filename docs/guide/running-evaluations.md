---
layout: doc
title: "Running Evaluations"
permalink: /guide/running-evaluations
---

# Running Evaluations

The `Controller` wires a target, an attacker, and a claim together and runs one
**threat model**. This page covers constructing it, what it returns, the live
progress output, the resumable results tree it writes, error handling, and how to
sweep several threat models.

## One Controller is one threat model

A threat model is a `(scope, llm_config, include_feedback)` triple: what the
attacker controls, what model and budget it has, and whether it learns how its
attacks were scored. **One `Controller` evaluates one claim under one threat
model.** Comparing threat models means building several Controllers (see
[Sweeping](#sweeping-multiple-threat-models) below).

Feedback is the subtlest of the three: `include_feedback=False` sets
`RunEndEvent.evaluation = None`, so the attacker gets no score signal and cannot
adapt to it (the run still happens and is still scored in the results). Comparing
`True` against `False` for the same scope is a common experiment: does giving the
attacker feedback make it more effective?

## Construction

```python
from superred.core.controller import Controller, TargetFactory
from superred.core.types.llm import LLMConfig

target_factory = TargetFactory(
    create=lambda: MyTarget(api_key="sk-...", api_base="https://proxy"),
    concurrency=8,                       # tasks in parallel; default 1
)

controller = Controller(
    optimizer_factory=lambda: MyOptimizer(),   # fresh attacker per task
    target_factory=target_factory,             # fresh target per task
    security_claim=claim,
    scope=frozenset({user_tag}),               # required, non-empty
    llm_config=LLMConfig(                       # optional: omit for non-LLM attackers
        model="gpt-4o-mini",
        api_base="https://proxy",
        api_key="sk-...",
    ),
    task_cost_cap_usd=5.00,                     # per-task attacker budget (USD); None = unlimited
    max_runs_per_task=100,                      # safety cap; None (the default) means 100
    include_feedback=True,                      # attach evaluation to RunEndEvent; default True
    # --- output ---
    persist=True,                               # write a results tree (default True; False = nothing)
    results_dir=None,                           # results folder; None = SUPERRED_RESULTS_DIR or ./superred-results/
    report="auto",                              # live dashboard on a TTY, plain lines otherwise; False = silent
)

result = await controller.run()                 # -> ThreatModelResult
```

| Parameter | Meaning |
|-----------|---------|
| `optimizer_factory` | zero-arg callable returning a fresh `Optimizer` (one per task) |
| `target_factory` | a `TargetFactory`, which bundles how to build the target with how many run in parallel (`concurrency`) |
| `security_claim` | the tasks to evaluate |
| `scope` | a non-empty `frozenset` of tags: the attacker's visible boundary |
| `read_only` | optional `frozenset` of extra visible-but-not-injectable tags; omit (default) for all-read & write |
| `llm_config` | the attacker's model and API access, or omit for non-LLM attackers |
| `task_cost_cap_usd` | per-task attacker spend cap in USD; `None` (default) means unlimited |
| `max_runs_per_task` | per-task run cap (>= 1); `None` (default) means 100 |
| `include_feedback` | whether the optimizer sees evaluation results; default `True` |
| `persist` | write a results tree; default `True`, pass `False` to write nothing |
| `results_dir` | the results folder; omit for `SUPERRED_RESULTS_DIR` or `./superred-results/` |
| `overwrite` | force a full recompute of an existing (resumable) experiment; by default (`False`) a re-run skips tasks that already finished and redoes only errored ones |
| `report` | `"auto"`/`True` show live progress (dashboard on a TTY, plain lines otherwise), `False` is silent |
| `attacker_label` / `target_label` / `claim_label` | short names for the experiment folder + dashboard |

For tests or a single expensive instance, `TargetFactory.singleton(target)`
wraps one instance and locks `concurrency` to 1. The Controller still calls
`teardown()` once per task, so a singleton that serves several tasks has its
`teardown()` called repeatedly: make it safe to call more than once (calls after
the first should be harmless no-ops).

## Running

The Controller does not create an event loop; you provide one:

```python
import asyncio

async def main():
    controller = Controller(...)
    result = await controller.run()

asyncio.run(main())
```

For each task the Controller builds a fresh target and optimizer, configures the
target, runs the optimizer loop until it signals `done` or hits `max_runs_per_task`,
evaluates each run, then tears everything down. Tasks run concurrently up to
`target_factory.concurrency`, but results come back in claim order. It returns a
`ThreatModelResult`.

### What you see when you run

The Controller streams live progress the whole way through:

- On a real interactive terminal you get a **live dashboard**: a top bar with
  overall progress (tasks done, attack-success rate, running count, cost, elapsed),
  then one block per threat model showing its own identity
  (attacker/target/claim/model/scope/budget) and metrics, with the tasks currently
  running listed indented beneath it (each with its live run/score/cost). The claim
  shows on that identity line too. A final results view renders when the run ends.

  <figure class="doc-figure">
    <img src="/assets/img/run-live-terminal.png" alt="superred's live terminal dashboard during a run: a header line with overall progress (task count, attack-success rate, running count and attacker spend) above a per-threat-model block showing its identity and metrics, with the currently running tasks listed indented beneath it.">
    <figcaption>The live dashboard on an interactive terminal, updating as the run proceeds.</figcaption>
  </figure>
- On a non-TTY, in CI, under `NO_COLOR`, or when output is piped, it degrades
  automatically to **plain lines**: a start banner, one line per task, and an end
  summary.

  <figure class="doc-figure">
    <img src="/assets/img/run-plain-output.png" alt="superred's plain-line output on a non-TTY: a start banner naming the threat model (scope, model, attacker, target, claim, task count, concurrency, budget), a line for the completed task with its outcome, score, run count and cost, and an end summary with the attack-success rate, highest score, and total attacker calls, cost and elapsed time.">
    <figcaption>The plain-line fallback used off a TTY (in CI, piped output, or under NO_COLOR): a start banner, one line per task, and an end summary.</figcaption>
  </figure>
- Several Controllers run through `run_all` on a TTY share **one** dashboard, one
  block each (so a sweep of differing threat models stays accurate: each block
  carries its own identity). See "Sweeping multiple threat models" below.

  <figure class="doc-figure">
    <img src="/assets/img/run-sweep-dashboard.png" alt="superred's shared live dashboard for a sweep of six threat models: a header with overall progress (tasks done, attack-success rate, running count, attacker spend, threat-model count) above one row per threat model, each carrying its own attacker, target, claim, model, scope and budget with progress, ASR, score, outcome counts and cost; some rows running with their tasks expanded, others queued.">
    <figcaption>One shared dashboard for a sweep through run_all: each threat model gets its own row, running ones expanded to their live tasks, queued ones waiting.</figcaption>
  </figure>

**Turning it off.** Pass `report=False` for silence.

## Reading the result

### ThreatModelResult

```python
result.scope            # the frozenset of tags this run tested
result.llm_config       # the LLMConfig used, or None
result.task_results     # list[TaskResult], in claim order
result.skipped_tasks    # tasks that raised NotApplicable during configure
```

### TaskResult (one per task)

```python
tr = result.task_results[0]
tr.task             # the Task
tr.success          # True if ANY run achieved the goal
tr.best_score       # highest primary Score across runs
tr.best_evaluation  # the EvaluationResult that produced best_score
tr.runs             # list[RunResult], one per run
tr.llm_usage        # total attacker LLM usage for this task (calls, cost)
tr.stop_reason      # "done" | "max_runs" | "budget_exhausted" | "error"
tr.error            # formatted traceback string, or None
```

`stop_reason` tells you *why the task stopped*: the optimizer signalled done, the
run cap was hit, the attacker's budget ran out, or an unexpected exception
abandoned the task. `error` carries the traceback when something went wrong.
Treat the two as independent: `error` can be set as a diagnostic even when
`stop_reason` is a clean value (e.g. the optimizer raised during teardown after a
normal finish).

### RunResult (one per run)

```python
run = tr.runs[0]
run.trajectory       # the full Trajectory for this run
run.evaluation       # the EvaluationResult for this run
run.llm_usage        # cumulative attacker usage AFTER this run
run.run_usage_delta  # THIS run's own usage (calls, cost)
run.started_at       # wall-clock UTC bounds, or None
run.ended_at
run.evaluated        # True if the score came from the evaluator
run.errored          # True if the run raised mid-execution
run.done             # True if the optimizer signalled stop after this run
```

`run.llm_usage` is **cumulative** (each run includes all prior usage), which is
exactly what you want for budget-versus-performance curves. For **per-run** cost,
use `run.run_usage_delta`: summing deltas across a task equals the task total,
whereas summing the cumulative snapshots over-counts.

### Inspecting a trajectory

The trajectory is the unified event log; there is no separate log. Query items
by type:

```python
from superred.core.types.events import (
    ControllableInjection,
    ControllablePreCallEvent,
    ObservableEvent,
    RunEndEvent,
)

for item in run.trajectory.snapshot():
    if isinstance(item, ControllablePreCallEvent):
        print("injection point:", item.controllable.name)
    elif isinstance(item, ControllableInjection):
        print("injected:", item.value)
    elif isinstance(item, ObservableEvent):
        print(f"{item.observable.name}: {item.content}")
    elif isinstance(item, RunEndEvent) and item.evaluation is not None:
        print("score:", item.evaluation.primary_score.value)
```

`RunStartEvent` is not in the trajectory; `RunEndEvent` is.

## Error handling: failures are contained per task

A single bad task does not abort the whole evaluation. If the optimizer, target,
or evaluator raises during a task's run loop, that task ends with
`stop_reason="error"`, its partial trajectory and traceback are preserved, and
**the remaining tasks still run**. Errors before the run loop even starts (a
failing `configure_target`, a constructor that throws) are likewise caught and
recorded as a synthetic error `TaskResult`. `NotApplicable` is handled
separately: the task is skipped into `skipped_tasks`.

This means `await controller.run()` rarely raises; instead you inspect
`stop_reason`/`error` per task. Teardown always runs.

## Persistence

Persistence is **on by default**. Every run writes a self-describing directory
tree under the results folder:

```
{results_folder}/
├── experiments.json                    # cross-experiment index
└── {slug}-{hash8}/                      # one experiment (one threat model)
    ├── manifest.json                    # params + summary + tasks[]
    ├── result.json                      # claim-level final metrics (completion marker)
    ├── logs/diagnostics.log
    └── tasks/
        └── 00001__{goalslug}/           # latest result for this task
            ├── task.json                # per-task result + metrics
            ├── iterations.json          # per-run score/metric progression
            └── trajectories/run_00001.json
```

- **Where results go.** `results_dir` is the **root** (the parent of the
  experiment folders), not a single file's directory. Omit it and results land
  in `SUPERRED_RESULTS_DIR` if set, else `./superred-results/`. The folder name
  `{slug}-{hash8}` is `attacker__target__claim__model` plus a hash of the full
  measurement identity, so distinct threat models never collide and a sweep can
  share one root (the `experiments.json` index ties them together).
- **Incremental + interruptible.** Each task's directory is published the moment
  it finishes, so an interrupted run leaves every completed task on disk.
  `result.json` is written last as the completion marker; a `manifest.json`
  without a `result.json` marks an interrupted run.
- **Resume.** Re-running the same Controller resolves to the same folder and
  **resumes**: tasks that already produced a valid measurement (`success`,
  `failed`, `budget_exhausted`) are kept; only `error`/interrupted/missing tasks
  recompute. Pass `overwrite=True` to force a full recompute. Reruns are
  crash-safe: the prior state is snapshotted into `previous_NN/` before any
  change.
- **Metrics.** `result.json`'s `summary` carries the attack-success rate and a
  stop-reason histogram: `asr`, `n_tasks`, `n_success`, `n_completed`,
  `n_failed`, `n_error`, `n_budget_exhausted`, `n_skipped`,
  `max/mean_primary_score`, `total_llm_usage`. Each `task.json` holds that task's
  metrics and `error` traceback; `iterations.json` and the `trajectories/` files
  hold the per-run detail.

{% include diagrams/u7.html %}

**Turning it off.** Pass `persist=False` to write nothing. Combine with
`report=False` for a completely quiet, non-writing run.

The framework also ships an HTML dashboard (dropped into the tree
on write) to browse the metrics, filter tasks by outcome, and drill into runs and
trajectories. Open it with the bundled CLI, which serves the directory and opens
your browser:

```bash
superred serve ./superred-results
```

(The page fetches the JSON in its directory, so a browser cannot read it from a
`file://` URL; `superred serve` runs the tiny local server for you.)

<figure class="doc-figure">
  <img src="/assets/img/results-web-report.png" alt="The superred web dashboard for a results directory: overall attack success rate and attacker cost, a run-outcomes bar, and a per-task table you can filter by outcome and expand to open each run's trajectory.">
  <figcaption>The static HTML dashboard served by superred serve: metrics, outcome filters, and per-task drill-down into runs and trajectories.</figcaption>
</figure>

**Reading results back.** Do not hand-parse the tree. `superred.core.persistence`
exposes public readers:

```python
from superred.core.persistence import (
    load_experiments_index, load_manifest, load_result,
    iter_tasks, load_task, load_iterations, load_trajectory,
)

for row in load_experiments_index("superred-results")["experiments"]:
    exp_dir = f"superred-results/{row['dir']}"
    summary = load_result(exp_dir)["summary"]
    print(row["slug"], summary["asr"], summary["n_success"])
    for view in iter_tasks(exp_dir):        # scalar view per task
        print(" ", view.status, view.best_score, view.goal)
```

> **Security caveat.** This is a red-teaming framework: persisted trajectories
> contain jailbreaks, planted secrets, and exfiltrated content, and are **not**
> scrubbed. `LLMConfig` writes `{model}` only (`api_key`/`api_base` are never
> written), but treat the **whole results folder as sensitive**, and keep
> credentials out of prompts, observables, and config values (they flow verbatim
> into the trajectory files).

## Sweeping multiple threat models

Building the sweep is deliberately the caller's job, one Controller per threat
model. That is what keeps you in full control of which experiments run: sweep any
mix of scopes, attacker models, budgets, and feedback settings, exactly the cells
you care about and nothing you do not, a dense grid or a handful of points. The
framework does the running for you: `run_all` drives the whole set concurrently
and renders it into one shared live dashboard.

```python
from superred.core.controller import run_all

scopes = [frozenset({USER_TAG}), frozenset({USER_TAG, SYSTEM_PROMPT_TAG})]
controllers = [
    Controller(..., scope=scope, results_dir="results")   # one shared folder; a subfolder per cell
    for scope in scopes
]
results = await run_all(controllers, concurrency=2)        # <=2 at once; results in input order
```

`run_all` owns a single canvas for the whole sweep, so the threat models render
as one clean view, one block each. A bare
`await asyncio.gather(*(c.run() for c in controllers))` still runs and persists
correctly, but each `run()` grabs the live dashboard independently, so under a
concurrency cap the canvas can stop, re-arm, and mix with plain lines; prefer
`run_all` for a shared live display. The target factory must be safe to call
many times.

## A complete example

This mirrors a real chatbot experiment: a Crescendo attacker against a chatbot
target, judged by SORRY-Bench, with **separate** attacker and judge budgets.

```python
import asyncio
import os

from dotenv import load_dotenv

from superred.core.controller import Controller, TargetFactory
from superred.core.types.llm import LLMConfig
from chatbot_target import ChatbotTarget, USER_TAG, MODEL_TAG  # ⚠️ non-release module name
from crescendo_optimizer import CrescendoOptimizer  # ⚠️ non-release module name
from security_claim_sorry_bench import sorry_bench_claim  # ⚠️ non-release module name


async def main() -> None:
    load_dotenv()
    api_base = os.environ["LITELLM_API_BASE"]
    api_key = os.environ["LITELLM_API_KEY"]
    target_model = "gpt-4o-mini"

    target_factory = TargetFactory(
        create=lambda: ChatbotTarget(model=target_model, api_base=api_base, api_key=api_key),
        concurrency=8,
    )

    # The judge gets its OWN LLMConfig, separate from the attacker's.
    claim = sorry_bench_claim(
        target_model_id=target_model,
        judge_llm_config=LLMConfig(model="openai/gpt-4-turbo-2024-04-09",
                                   api_base=api_base, api_key=api_key),
        prompts_per_category=2,
    )

    controller = Controller(
        optimizer_factory=lambda: CrescendoOptimizer(),
        target_factory=target_factory,
        security_claim=claim,
        scope=frozenset({USER_TAG}),
        read_only=frozenset({MODEL_TAG}),   # read the responses, cannot rewrite them
        llm_config=LLMConfig(model="gpt-4o", api_base=api_base, api_key=api_key),
        task_cost_cap_usd=5.0,
        include_feedback=True,
        results_dir="results",            # the results folder; this run lands in its own subfolder
        attacker_label="crescendo",       # short names used in the folder + dashboard
        target_label="chatbot",
        claim_label="sorry-bench",
    )

    result = await controller.run()
    succ = sum(1 for tr in result.task_results if tr.success)
    print(f"{succ}/{len(result.task_results)} prompts jailbroken")


asyncio.run(main())
```

For the design rationale behind all of this (per-task lifecycle, the middleware
pipeline, exact persistence format), see the [Controller reference](/reference/controller).
