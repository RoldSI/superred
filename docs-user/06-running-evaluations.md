# Running Evaluations

The `Controller` wires a target, an attacker, and a claim together and runs one
**threat model**. This page covers constructing it, what it returns, persistence,
error handling, and how to sweep several threat models.

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
        max_cost=5.00,                          # USD budget; None = unlimited
    ),
    max_runs_per_task=100,                      # safety cap; None (the default) means 100
    include_feedback=True,                      # attach evaluation to RunEndEvent; default True
    results_dir="results/run-1",                # optional: persist JSON
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
| `results_dir` | where to write result JSON, or omit to write nothing |

Two things people get wrong coming from older versions:

- You pass **factories**, not instances (`optimizer_factory=`, `target_factory=`),
  because the Controller builds a fresh one per task.
- You pass **`scope`** (a `frozenset` of tags), not a single tag. Even a
  single-boundary scope is `frozenset({tag})`. By default everything in `scope`
  is read & write; pass a **`read_only`** set to add tags the attacker can see
  but not inject into — see
  [Security Domains](07-security-domains.md#access-levels-read-only-surfaces).

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
`target_factory.concurrency`, but results come back in claim order. It prints a
summary to stdout and returns a `ThreatModelResult`.

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
    run.trajectory     # the full Trajectory for this run
    run.evaluation     # the EvaluationResult for this run
    run.llm_usage      # cumulative attacker usage AFTER this run

    for item in run.trajectory.snapshot():
        ...            # inspect events/responses by isinstance
    print(run.evaluation.primary_score.value, run.evaluation.success)
```

`run.llm_usage` is **cumulative**: each run includes all prior usage, which is
exactly what you want for budget-versus-performance curves.

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

## Persistence (`results_dir`)

Pass `results_dir` and the Controller writes structured JSON:

```
results/run-1/
├── {scope}__{model}.json          # claim-level summary (the completion marker)
└── {scope}__{model}/
    ├── 00001__{goal}.json          # one self-contained file per task
    └── ...
```

- Per-task detail files are written **incrementally**, as each task finishes, so
  an interrupted run still leaves every completed task on disk.
- The summary file is written last and acts as a completion marker: if you see
  the subfolder but not the summary, the run was interrupted.
- The summary holds aggregates (`n_tasks`, `n_success`, `n_skipped`,
  `max/mean_primary_score`, `total_llm_usage`); each detail file holds the full
  runs and trajectories plus `stop_reason` and the `error` traceback.
- **Secrets**: `LLMConfig.api_key` and `api_base` are excluded. Trajectory
  contents are **not** scrubbed, so keep credentials out of prompts, observables,
  and config values.
- **Collisions raise** `FileExistsError` rather than overwriting; use a fresh
  subdirectory per run. Several Controllers pointed at the same `results_dir`
  (the sweep pattern) each write their own scope/model-named pair safely.

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
            results_dir=f"results/{name}",
        )
        result = await controller.run()
        succ = sum(1 for tr in result.task_results if tr.success)
        print(f"{name}: {succ}/{len(result.task_results)} succeeded")
```

You can run the Controllers concurrently instead with
`await asyncio.gather(*(c.run() for c in controllers))`, as long as each has its
own `results_dir` (or none) and the target factory is safe to call many times.

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
                                   api_base=api_base, api_key=api_key, max_cost=10.0),
        prompts_per_category=2,
    )

    controller = Controller(
        optimizer_factory=lambda: CrescendoOptimizer(),
        target_factory=target_factory,
        security_claim=claim,
        scope=frozenset({USER_TAG, RESPONSE_READABLE_TAG}),
        llm_config=LLMConfig(model="gpt-4o", api_base=api_base, api_key=api_key, max_cost=5.0),
        include_feedback=True,
        results_dir="results/crescendo-user_response",
    )

    result = await controller.run()
    succ = sum(1 for tr in result.task_results if tr.success)
    print(f"{succ}/{len(result.task_results)} prompts jailbroken")


asyncio.run(main())
```

For the design rationale behind all of this (per-task lifecycle, the middleware
pipeline, exact persistence format), see [`../docs/controller.md`](../docs/controller.md).
