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

A threat model is a `(scope, llm_config)` pair: what the attacker controls, and
what model/budget it has. **One `Controller` evaluates one claim under one threat
model.** Comparing threat models means building several Controllers (see
[Sweeping](#sweeping-multiple-threat-models) below).

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
    # --- output (new in 0.3.0) ---
    persist=True,                               # write a results tree (default True; False = nothing)
    results_dir=None,                           # results ROOT; None = SUPERRED_RESULTS_DIR or ./superred-results/
    report="auto",                              # live dashboard on a TTY, plain lines otherwise; False = silent
)

result = await controller.run()                 # -> ThreatModelResult
```

| Parameter | Meaning |
|-----------|---------|
| `optimizer_factory` | zero-arg callable returning a fresh `Optimizer` (one per task) |
| `target_factory` | a `TargetFactory`: how to build the target, and `concurrency` |
| `security_claim` | the tasks to evaluate |
| `scope` | a non-empty `frozenset` of tags: the attacker's visible boundary |
| `read_only` | optional `frozenset` of extra visible-but-not-injectable tags; omit (default) for all-read & write |
| `llm_config` | the attacker's model + budget, or omit for non-LLM attackers |
| `max_runs_per_task` | per-task run cap (>= 1); `None` (default) means 100 |
| `include_feedback` | whether the optimizer sees evaluation results; default `True` |
| `persist` | write a results tree; default `True`, pass `False` to write nothing |
| `results_dir` | the results **root** (parent of the experiment folders); omit for `SUPERRED_RESULTS_DIR` or `./superred-results/` |
| `overwrite` | force a full recompute of an existing (resumable) experiment; default `False` |
| `report` | `"auto"`/`True` show live progress (dashboard on a TTY, plain lines otherwise), `False` is silent |
| `reporter` | inject a custom `ProgressReporter` observer (wins over `report`) |
| `attacker_label` / `target_label` / `claim_label` | short names for the experiment folder + dashboard |

Two things people get wrong coming from older versions:

- You pass **factories**, not instances (`optimizer_factory=`, `target_factory=`),
  because the Controller builds a fresh one per task.
- You pass **`scope`** (a `frozenset` of tags), not a single tag. Even a
  single-boundary scope is `frozenset({tag})`. By default everything in `scope`
  is read & write; pass a **`read_only`** set to add tags the attacker can see
  but not inject into, see
  [Security Domains](/guide/security-domains#access-levels-read-only-surfaces).

For tests or a single expensive instance, `TargetFactory.singleton(target)`
wraps one instance and locks `concurrency` to 1. The Controller still calls
`teardown()` once per task, so a multi-task singleton needs an idempotent
teardown.

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

The Controller streams live progress the whole way through (it no longer prints a
single block at the end):

- On a real interactive terminal you get a **live dashboard**: a top bar with
  overall progress (tasks done, attack-success rate, running count, cost,
  elapsed), then one block per threat model showing its own identity
  (attacker/target/model/scope/claim/budget) and metrics, with the tasks currently
  running listed indented beneath it (each with its live run/score/cost). The
  claim shows on that identity line too. A
  final results view renders when the run ends.
- On a non-TTY, in CI, under `NO_COLOR`, or when output is piped, it degrades
  automatically to **plain lines**: a start banner, one line per task, and an
  end summary (which mirrors the old end-of-run summary block).
- Several Controllers run together with `asyncio.gather` on a TTY share **one**
  dashboard, one block each (so a sweep of differing threat models stays
  accurate: each block carries its own identity).

**Turning it off.** Pass `report=False` for silence, or inject your own observer
with `reporter=` (a `ProgressReporter` from `superred.core.reporting`).

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
for run in tr.runs:
    run.trajectory       # the full Trajectory for this run
    run.evaluation       # the EvaluationResult for this run
    run.llm_usage        # cumulative attacker usage AFTER this run
    run.run_usage_delta  # THIS run's own usage (calls, cost)
    run.started_at       # wall-clock UTC bounds, or None
    run.ended_at
    run.evaluated        # True if the score came from the evaluator
    run.errored          # True if the run raised mid-execution
    run.done             # True if the optimizer signalled stop after this run

    for item in run.trajectory.snapshot():
        ...              # inspect events/responses by isinstance
    print(run.evaluation.primary_score.value, run.evaluation.success)
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

## What gets written (persistence is on by default)

Persistence is **on by default**. Every run writes a self-describing directory
tree under the results root:

```
{results_root}/
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

**Turning it off.** Pass `persist=False` to write nothing (the pre-0.3.0
default). Combine with `report=False` for a completely quiet, non-writing run.

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
> written), but treat the **whole results root as sensitive**, and keep
> credentials out of prompts, observables, and config values (they flow verbatim
> into the trajectory files). The default `./superred-results/` is gitignored.

The framework also ships a generic static HTML dashboard (dropped into the tree
on write) to browse the metrics, filter tasks by outcome, and drill into runs
and trajectories. Open it with the bundled CLI, which serves the directory and
opens your browser:

```bash
superred serve ./superred-results
```

(The page fetches the JSON in its directory, so a browser cannot read it from a
`file://` URL; `superred serve` runs the tiny local server for you.)

## include_feedback: modelling a blind attacker

`include_feedback=False` sets `RunEndEvent.evaluation = None`: the optimizer gets
no score signal and cannot adapt to it (the run still happens and is still
scored in the results). Comparing `True` vs `False` for the same scope is a
common experiment: does giving the attacker feedback make it more effective?

## Sweeping multiple threat models

Sweeping is deliberately the caller's job: build one Controller per threat model.
Two patterns are used in practice.

### In-script sequential loop

Build a fresh Controller per scope and await them in turn:

```python
async def main():
    target_factory = TargetFactory(create=lambda: MyTarget(...), concurrency=8)
    scopes = {
        "user":        frozenset({USER_TAG}),
        "user+system": frozenset({USER_TAG, SYSTEM_PROMPT_TAG}),
    }
    for name, scope in scopes.items():
        controller = Controller(
            optimizer_factory=lambda: MyOptimizer(),
            target_factory=target_factory,
            security_claim=claim,
            scope=scope,
            llm_config=attacker_cfg,
            results_dir="results",     # ONE shared root; each scope lands in its own folder
        )
        result = await controller.run()
        succ = sum(1 for tr in result.task_results if tr.success)
        print(f"{name}: {succ}/{len(result.task_results)} succeeded")
```

The two scopes have different measurement identities, so they land in **separate
`{slug}-{hash8}` folders under the one root** (no collision), and the shared
`experiments.json` indexes both. You can run the Controllers concurrently instead
with `await asyncio.gather(*(c.run() for c in controllers))`; on a TTY they share
one live dashboard, one row each. The target factory must be safe to call many
times.

### One process per cell

The larger experiment scripts run **one Controller per process**, selecting the
cell from environment variables, so a sweep is a shell loop that launches the
script repeatedly. This isolates cells completely (separate logs, separate
crashes) and is the style used by the `RQ*` experiments:

```bash
SCOPE=user        INCLUDE_FEEDBACK=false python run.py
SCOPE=user        INCLUDE_FEEDBACK=true  python run.py
SCOPE=user+system INCLUDE_FEEDBACK=true  python run.py
```

## A complete example

This mirrors a real chatbot experiment: a Crescendo attacker against a chatbot
target, judged by SORRY-Bench, with **separate** attacker and judge budgets.

```python
import asyncio
import os

from dotenv import load_dotenv

from superred.core.controller import Controller, TargetFactory
from superred.core.types.llm import LLMConfig
from chatbot_target import ChatbotTarget, USER_TAG, RESPONSE_READABLE_TAG
from crescendo_optimizer import CrescendoOptimizer
from security_claim_sorry_bench import sorry_bench_claim


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
        scope=frozenset({USER_TAG, RESPONSE_READABLE_TAG}),
        llm_config=LLMConfig(model="gpt-4o", api_base=api_base, api_key=api_key),
        task_cost_cap_usd=5.0,
        include_feedback=True,
        results_dir="results",            # root; this run lands in its own folder inside it
        attacker_label="crescendo",       # short names used in the folder + dashboard
        target_label="chatbot",
        claim_label="sorry-bench",
    )

    result = await controller.run()
    succ = sum(1 for tr in result.task_results if tr.success)
    print(f"{succ}/{len(result.task_results)} prompts jailbroken")


asyncio.run(main())
```

## Running on AWS Bedrock

Both the attacker `LLMConfig` and the target accept any litellm model id, so you
can point them at Bedrock (`bedrock/...`) or Bedrock Mantle (`bedrock_mantle/...`)
models. Two requirements:

- **`litellm>=1.89.0`** (the framework already pins this). OpenAI models on
  Bedrock Mantle (`bedrock_mantle/openai.gpt-5.4`, `gpt-5.5`) are served through
  the Responses API; older litellm crashes routing them. With 1.89.0+ litellm
  bridges Chat Completions to the Responses API transparently.
- **The AWS SDK**: `pip install "superred[bedrock]"` (pulls in `boto3`).
  Authenticate with AWS credentials, or `BEDROCK_MANTLE_API_KEY` for Mantle
  OpenAI models, per the
  [litellm Bedrock docs](https://docs.litellm.ai/docs/providers/bedrock_mantle).

For the design rationale behind all of this (per-task lifecycle, the middleware
pipeline, exact persistence format), see the [Controller reference](/reference/controller).
