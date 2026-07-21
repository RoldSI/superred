---
layout: doc
title: "Results & Persistence"
permalink: /reference/results
---

# Results & Persistence

This page specifies what a run **produces**: the result objects returned in
memory, the structured tree written to disk, how a re-run resumes, how to read
results back, and how progress is reported live and served afterward.

`controller.run()` returns one [`ThreatModelResult`](#threatmodelresult). By
default it also **persists** a resumable results tree to disk and **streams**
live progress to the terminal. Both are on by default; both can be turned off.

## Result objects

Three frozen dataclasses nest: a `ThreatModelResult` holds one `TaskResult` per
task, and each `TaskResult` holds one `RunResult` per run.

### `RunResult`

One target execution plus its evaluation.

- `trajectory: Trajectory` the full run trajectory.
- `evaluation: EvaluationResult` this run's evaluation.
- `llm_usage: LLMUsage` **cumulative** optimizer usage after this run (it
  includes every prior run in the task). This is what a budget-versus-performance
  curve wants: each point is (total spent so far, score so far).
- `run_usage_delta: LLMUsage` (default empty) **this run's own** usage
  (`llm_usage` minus the previous run's cumulative snapshot). Summing the deltas
  across a task equals the task total; summing the cumulative snapshots
  over-counts. Use the delta for per-run cost.
- `started_at` / `ended_at: datetime | None` (default `None`) wall-clock UTC
  bounds.
- `evaluated: bool` (default `True`) whether the score came from the evaluator;
  `False` for the synthetic zero-score run appended on an error or budget path.
- `errored: bool` (default `False`) whether the run raised mid-execution.
- `done: bool` (default `False`) whether the optimizer signalled it wanted to
  stop after this run.

### `TaskResult`

All runs for one task.

- `task: Task[Target]` the task that was evaluated.
- `runs: list[RunResult]` every run, in order.
- `best_score: Score` the highest primary score across runs.
- `best_evaluation: EvaluationResult` the evaluation that produced `best_score`.
- `success: bool` whether any run achieved the goal.
- `llm_usage: LLMUsage` total optimizer usage for the task.
- `stop_reason: Literal["done", "max_runs", "budget_exhausted", "error"]` why the
  loop ended (see below).
- `scope: Scope` (default `frozenset()`) the read & write scope enforced for
  **this** task. In static mode it equals the Controller's `scope`; with a
  resolver it is the per-task resolved scope.
- `read_only: Scope` (default `frozenset()`) the read-only scope enforced for
  this task (analogous).
- `error: str | None` (default `None`) a formatted traceback when the controller
  observed an exception for this task. Treat it as **independent** of
  `stop_reason`: it is usually set with `stop_reason="error"`, but it is also
  populated as a diagnostic if a cleanly-classified task later raised during
  teardown, so `error is not None` does not imply `stop_reason == "error"`.
- `started_at` / `ended_at: datetime | None` (default `None`).
- `n_runs: int | None` (default `None`) an explicit run count. It is set for a
  **resumed** task, whose `runs` list is intentionally empty (its trajectories
  stay on disk, unread); `None` means "use `len(runs)`".

The four **stop reasons**: `"done"` (the optimizer returned
`RunEndResponse(done=True)`), `"max_runs"` (hit `max_runs_per_task`),
`"budget_exhausted"` (a `BudgetExhaustedError` ended the loop), and `"error"` (an
unexpected exception escaped the optimizer, target, or evaluator and the task was
abandoned with its partial trajectory preserved).

### `ThreatModelResult`

Everything for the one `(scope, llm_config)` this Controller measured.

- `scope: Scope` / `read_only: Scope` the run-level scopes. **In dynamic mode (a
  resolver) both are empty**; the per-task truth lives on each `TaskResult`.
- `llm_config: LLMConfig | None` the LLM config used, or `None` for a non-LLM run.
- `task_results: list[TaskResult]` one per evaluated task, in claim order (a
  resumed run merges kept and re-run tasks back into claim order).
- `task_cost_cap_usd: float | None` (default `None`) the attacker's per-task cap.
- `skipped_tasks: list[Task[Target]]` (default empty) tasks that raised
  `NotApplicable` (from `configure_target` or, in dynamic mode, a resolver).
- `scope_label: str | None` (default `None`) `None` in static mode; in dynamic
  mode the label that names the run (since `scope`/`read_only` are empty).
- `started_at` / `ended_at: datetime | None` (default `None`).

## Persistence

Persistence is **on by default** (`persist=True`). Set `persist=False` to write
nothing. When on, each run lands in one self-describing directory tree that the
[reader API](#reading-results-back), the [resume engine](#resume), and the
[web report](#the-web-report-and-superred-serve) all consume without hand-parsing.

The current on-disk schema is **version 4** (`SCHEMA_VERSION = 4`). Note this is
the persistence schema version, distinct from the framework version.

{% include diagrams/d5.html %}

(Lock files, `.experiments.lock` at the root and a `.lock` per experiment
directory, coordinate concurrent writers; they are advisory and not part of the
readable data.)

- **Results root.** `results_dir` is the **root**, the parent that holds one
  folder per experiment, not a single file. When omitted it resolves to the
  `SUPERRED_RESULTS_DIR` environment variable, else `./superred-results/`. Many
  Controllers in a sweep share one root, each landing in its own folder, and
  `experiments.json` indexes them all.
- **Experiment folder name `{slug}-{hash8}`.** `{slug}` is a short human label
  `{attacker}__{target}__{claim}__{model}` (sanitized, truncated; it does **not**
  list scope tags), taken from `attacker_label` / `target_label` / `claim_label`,
  each falling back to a factory or class name. `{hash8}` is eight hex of a
  sha256 over the **measurement identity** (attacker, target, claim, model, scope,
  read_only, budget, max_runs, feedback), so two distinct threat models never
  collide and an identical re-run resolves to the same folder (and resumes). The
  schema version is deliberately **excluded** from the identity, so a framework
  upgrade still resumes a prior run. When `llm_config` is `None`, the model
  segment is `no-llm`.
- **`result.json`** (written last, the completion marker): `schema_version`, an
  `experiment` block (identity plus display parameters), `timing`, and a
  `summary`. The summary carries `asr`, `n_tasks`, `n_success`, `n_completed`,
  `n_failed`, `n_error`, `n_budget_exhausted`, `n_skipped`, `max_primary_score`,
  `mean_primary_score`, and `total_llm_usage`. Here `n_completed = done +
  max_runs + budget_exhausted` and `asr = n_success / n_completed`, so errored
  and skipped tasks are excluded from the denominator.
- **`manifest.json`**: the same `experiment` and `summary` blocks, a `status`
  (`in_progress` / `complete`), and a scalar `tasks[]` index. It is rewritten as
  tasks land, so it is always current.
- **`tasks/{NNNNN}__{goalslug}/task.json`**: the per-task result, repeating
  `schema_version`, `index`, `goal`, `goal_hash`, that task's resolved
  `scope`/`read_only`, `llm_config` (model only), `task_cost_cap_usd`, plus
  `status`, `success`, `stop_reason`, `best_score`, `best_evaluation`, `n_runs`,
  `llm_usage`, `timing`, and `error`. Published the moment the task finishes, so
  an interrupted run leaves every completed task on disk.
- **`iterations.json`**: the per-run progression, one entry per run with
  `primary_score`, `success`, the `evaluated`/`errored`/`done` flags, per-run
  `usage_delta` and `usage_cumulative`, `timing`, and a relative path to the run's
  trajectory file.
- **`trajectories/run_NNNNN.json`**: one file per run, the full serialized
  trajectory of events and responses.

**Atomicity and crash safety.** Every file is written to a temp path and then
`os.replace`d; every task directory is published as a temp directory and then
renamed. `manifest.json` reads `status="in_progress"` while a run is live and
flips to `"complete"` only once `result.json` is written last, so an interrupted
run is recognizable by its still-`in_progress` manifest.

### Resume

Because the folder name **is** the measurement identity, re-running the same
Controller resolves to the same folder and **resumes** rather than colliding:

- A task whose prior result was a valid measurement (`success`, `failed`, or
  `budget_exhausted`) is **kept** and not re-run. Only `error`, interrupted, or
  missing tasks recompute.
- A task is matched to its prior result by (same 1-based index + same goal content
  hash), so appending tasks to a claim resumes the existing ones and computes only
  the new.
- `overwrite=True` forces a full recompute of every task.
- Kept tasks are folded back into the returned `ThreatModelResult` from disk with
  faithful scalar metrics but an **empty `runs` list** (their trajectories stay on
  disk); `TaskResult.n_runs` carries the real count.
- **Crash-safe.** Before any current file changes, the prior complete state is
  snapshotted immutably into the next `previous_NN/`. Kept tasks are shared into
  the snapshot by hardlink (copy fallback), so they belong to both the snapshot
  and the current state at no extra disk cost, and an interrupted re-run can never
  destroy the only copy of a prior result.

### Reading results back

`superred.core.persistence` exposes a public reader API, so analysis code (and
the web report) never hand-parses the tree:

```python
from superred.core.persistence import (
    load_experiments_index,   # (results_root)          -> the cross-experiment index
    load_manifest,            # (experiment_dir)         -> params + summary + tasks[]
    load_result,              # (experiment_dir)         -> claim-level final metrics
    iter_tasks,               # (experiment_dir)         -> list[TaskView] (one scalar view/task)
    iter_task_dirs,           # (experiment_dir)         -> list[Path] (the task directories)
    load_task,                # (task_dir)               -> per-task result + metrics
    load_iterations,          # (task_dir)               -> per-run progression
    load_trajectory,          # (task_dir, run_number)   -> one run's full trajectory
)
```

`iter_tasks` returns `TaskView` objects, a flat scalar view per task (index,
goal, `goal_hash`, dir, status, success, stop reason, best score, run count, cost,
timing, error), enough to build a summary table without loading trajectories.

### Security: persisted content is sensitive

**This is a red-teaming framework. Persisted trajectories contain jailbreaks,
planted secrets, and exfiltrated content, and they are NOT scrubbed.** `LLMConfig`
serializes `{model}` only (`api_key` and `api_base` are never written), but that
is the only redaction. Treat the whole results root as **sensitive**: it holds
working attacks and whatever the target leaked under them. Keep credentials out of
prompts, observable payloads, and config values, since those flow verbatim into
the trajectory files. The default root (`./superred-results/`) should be
gitignored.

## Live progress reporting

The Controller prints nothing itself. It narrates a run through a **reporter**, an
observer it calls at each lifecycle point. Two constructor arguments choose one:

- **`report: bool | Literal["auto"] = "auto"`.** `True` / `"auto"` show progress;
  `False` is silent. What "show" means degrades to the environment automatically:
  - On an **interactive terminal**, a live **dashboard** (a `rich` canvas): a top
    bar with overall progress (tasks done, attack-success rate, running count,
    cost, elapsed), then one block per threat model with its identity and
    metrics, and the running tasks listed beneath it. A final results view renders
    at the end.
  - Otherwise it falls back to **plain line output**: a start banner, one line per
    completed task, and an end summary. The plain banner and summary carry the
    same content, so nothing is lost when the canvas is unavailable.
  - It falls back to plain when output is not a TTY, when `CI` is set, when
    `TERM=dumb`, when `TERM=dumb` **and** `NO_COLOR` are set together, or when
    `SUPERRED_NO_DASHBOARD` is set. (`NO_COLOR` on its own only strips color; it
    does not by itself force plain output.)
- **`reporter: ProgressReporter | None = None`.** Inject your own observer (a
  custom sink, a metrics pipe, a test double). It wins over `report`.

### The `ProgressReporter` protocol

`ProgressReporter` is a runtime-checkable `Protocol` in `superred.core.reporting`.
Every method is called on the event-loop thread and must not block or await:

```python
on_threat_model_start(ctx)   on_task_start(ev)       on_run_complete(ev)
on_task_complete(ev)         on_task_skipped(ev)      on_diagnostic(ev)
on_threat_model_end(ev)
```

Each receives a frozen payload (`ThreatModelContext`, `TaskStartEvent`,
`RunCompleteEvent`, and so on) describing that moment. The built-in reporters are
`NullReporter` (silent), `PlainReporter` (lines), and `Dashboard` (the canvas).

### Concurrent Controllers share one dashboard

A sweep run through [`run_all`](/reference/controller#sweeping-multiple-threat-models)
renders every threat model into a **single** shared canvas, one lane each, rather
than fighting over the terminal: `run_all` owns one `Dashboard`, calls
`expect(n)`, and pre-registers a lane per Controller, and the dashboard stays
alive until all `n` lanes finish (so a capped sweep that pauses between waves does
not tear the canvas down). A bare `asyncio.gather(*(c.run() ...))` runs and
persists correctly but does not coordinate the display: each `run()` grabs the
process-global dashboard independently, so its live output can mix. `rich`
(`>=14,<15`) is a core dependency.

## The web report and `superred serve`

The framework ships a single self-contained static page, `dashboard.html`, that
reads a results tree in the browser: it shows the metrics, filters tasks by
outcome (success / failure / error), and drills into each task's runs and
trajectories. It needs no build step and is dropped into the results root (and
each experiment folder) on every finalize, so it always matches the installed
version.

Because the page fetches the JSON files next to it, browsers block those fetches
from `file://`. The bundled CLI runs a tiny local server so you do not have to:

```bash
superred serve ./superred-results     # serve a results root, open the report
```

`superred serve [dir]` (the directory defaults to `superred-results`) rewrites the
freshest `dashboard.html` into the directory, starts a local HTTP server, and
opens the report in your browser. Flags: `--host` (default `127.0.0.1`), `--port`
(default `8000`, falling back to a free port if it is taken), and `--no-browser`.
This is the only subcommand today; the CLI serves results, it does not run
experiments. Running an evaluation is done in Python via
`asyncio.run(controller.run())`.
