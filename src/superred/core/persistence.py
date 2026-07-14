"""Persistence helpers for ``ThreatModelResult`` artifacts.

Module-private. Imported only by :mod:`superred.core.controller`. No
public re-exports — opting into persistence is a single keyword argument
on the :class:`Controller` constructor.

Layout (per completed threat model):

* ``{results_dir}/{scope}__{model}.json`` — claim-level summary with
  one entry per task plus aggregates (mean/max primary score, success
  count, total LLM usage). Each task entry references its detail file.
* ``{results_dir}/{scope}__{model}/{NNNNN}__{goal}.json`` — one detail
  file per task, containing all runs (trajectories, evaluations, LLM
  usage). Tasks are 1-indexed; the index is zero-padded to 5 digits and
  the suffix is the sanitized goal description (truncated).

Incremental writes: each per-task detail file is written as soon as
that task finishes (success or error), so a controller that aborts
mid-iteration still leaves every completed task on disk for offline
inspection. The claim-level summary lands at the very end and acts as
a completion marker — if it's missing, the run was interrupted.

The ``{scope}`` stem joins the sorted read & write tag names.  When the
threat model also has read-only tags, those names are appended as a
``__ro_{read_only}`` component so threat models differing only in access
mode don't collide; the full ``scope`` (read & write) and ``read_only``
tag lists are also recorded as JSON fields in both file kinds.  In
dynamic-scope mode (the Controller given a per-task scope resolver) there
is no single run scope, so the ``{scope}`` stem is the run's
``scope_label`` and each per-task detail file records that task's own
resolved scope; the claim-level ``scope``/``read_only`` fields are then
empty and ``scope_label`` carries the run identity.

All files are written atomically (temp file + ``rename``).

``LLMConfig`` fields ``api_key`` and ``api_base`` are explicitly
excluded from serialization. Trajectory contents are not scrubbed for
secrets — the caller is responsible for not putting credentials into
log/observable payloads.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from superred.core.types.controllable import Controllable
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.event import Event, EventResponse
from superred.core.types.events import (
    ControllableInjection,
    ControllableNoInjection,
    ControllablePostCallEvent,
    ControllablePreCallEvent,
    ObservableEvent,
    RunEndEvent,
    RunEndResponse,
)
from superred.core.types.llm import LLMConfig, LLMUsage
from superred.core.types.observable import Observable
from superred.core.types.security_domain import Scope, SecurityDomainTag
from superred.core.types.trajectory import Trajectory

if TYPE_CHECKING:
    from superred.core.controller import RunResult, TaskResult, ThreatModelResult


SCHEMA_VERSION = 2

_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9_-]")
_TASK_FILENAME_MAX_GOAL = 50


def _sanitize_segment(s: str) -> str:
    """Replace any character outside ``[A-Za-z0-9_-]`` with ``_``."""
    return _SAFE_SEGMENT_RE.sub("_", s)


def _sorted_names(scope: Scope) -> list[str]:
    """Sorted tag names of *scope*."""
    return sorted(t.name for t in scope)


def _scope_stem(scope: Scope, read_only: Scope, scope_label: str | None = None) -> str:
    """Filename stem for a threat model's artifacts.

    In dynamic-scope mode *scope_label* names the run (no single concrete scope
    exists) and is used verbatim (sanitized).  Otherwise the stem is the
    sorted, ``.``-joined read & write tag names; when ``read_only`` is
    non-empty a ``__ro_{read_only}`` component is appended so two threat models
    that differ only in access mode get distinct stems.  With no read-only tags
    the stem is just the scope (so the common all-read & write filenames are
    unchanged from a no-access-control run).
    """
    if scope_label is not None:
        return _sanitize_segment(scope_label)
    scope_part = ".".join(_sanitize_segment(n) for n in _sorted_names(scope))
    if not read_only:
        return scope_part
    ro_part = ".".join(_sanitize_segment(n) for n in _sorted_names(read_only))
    return f"{scope_part}__ro_{ro_part}"


def _filename_for(
    scope: Scope, read_only: Scope, llm_config: LLMConfig | None, scope_label: str | None = None
) -> str:
    """Deterministic filename for the claim-level file.

    Format: ``{scope_stem}__{sanitized_model}.json`` (see :func:`_scope_stem`
    for the stem, including the dynamic-mode ``scope_label``). ``llm_config is
    None`` becomes ``no-llm``.
    """
    model_part = _sanitize_segment(llm_config.model) if llm_config is not None else "no-llm"
    return f"{_scope_stem(scope, read_only, scope_label)}__{model_part}.json"


def _subfolder_for(
    scope: Scope, read_only: Scope, llm_config: LLMConfig | None, scope_label: str | None = None
) -> str:
    """Deterministic name of the per-task subfolder for a threat model.

    Same stem as :func:`_filename_for` minus the ``.json`` suffix.
    """
    return _filename_for(scope, read_only, llm_config, scope_label).removesuffix(".json")


def _task_filename(index: int, goal_description: str) -> str:
    """Filename for a single task within a threat model subfolder.

    Format: ``{NNNNN}__{sanitized_truncated_goal}.json``. *index* is
    1-based and zero-padded to 5 digits. The goal description is
    sanitized and truncated to keep filenames manageable; if the
    sanitized form is empty, ``task`` is used as a placeholder.
    """
    sanitized = _sanitize_segment(goal_description)[:_TASK_FILENAME_MAX_GOAL].rstrip("_")
    suffix = sanitized or "task"
    return f"{index:05d}__{suffix}.json"


# ---------------------------------------------------------------------------
# Per-type serializers
# ---------------------------------------------------------------------------


def _tag_name(tag: SecurityDomainTag | None) -> str | None:
    return tag.name if tag is not None else None


def _serialize_controllable(c: Controllable) -> dict[str, Any]:
    return {
        "name": c.name,
        "security_domain": c.security_domain.name,
        "description": c.description,
        "value_type": c.value_type,
    }


def _serialize_observable(o: Observable) -> dict[str, Any]:
    return {
        "name": o.name,
        "security_domain": o.security_domain.name,
        "description": o.description,
        "observable_type": o.observable_type,
    }


def _serialize_score(s: Score) -> dict[str, Any]:
    return {
        "name": s.name,
        "value": s.value,
        "security_domain": _tag_name(s.security_domain),
    }


def _serialize_evaluation(e: EvaluationResult) -> dict[str, Any]:
    return {
        "success": e.success,
        "primary_score": _serialize_score(e.primary_score),
        "sub_scores": {k: _serialize_score(v) for k, v in e.sub_scores.items()},
        "rationale": e.rationale,
    }


def _serialize_llm_config(cfg: LLMConfig | None) -> dict[str, Any] | None:
    """Allowlist serialization. Excludes ``api_key`` and ``api_base``."""
    if cfg is None:
        return None
    return {"model": cfg.model}


def _serialize_llm_usage(u: LLMUsage) -> dict[str, Any]:
    return {"calls": u.calls, "cost": u.cost}


def _event_base(event: Event) -> dict[str, Any]:
    return {
        "kind": "event",
        "type": type(event).__name__,
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "security_domain": _tag_name(event.security_domain),
    }


def _serialize_event(event: Event) -> dict[str, Any]:
    payload = _event_base(event)
    if isinstance(event, ControllablePreCallEvent):
        payload["controllable"] = _serialize_controllable(event.controllable)
        payload["request"] = event.request
    elif isinstance(event, ControllablePostCallEvent):
        payload["controllable"] = _serialize_controllable(event.controllable)
        payload["request"] = event.request
        payload["answer"] = event.answer
    elif isinstance(event, ObservableEvent):
        payload["observable"] = _serialize_observable(event.observable)
        payload["content"] = event.content
    elif isinstance(event, RunEndEvent):
        payload["evaluation"] = (
            _serialize_evaluation(event.evaluation) if event.evaluation is not None else None
        )
    # Other Event subclasses (including RunStartEvent, which is never
    # persisted to the trajectory) fall through with just the base fields.
    return payload


def _serialize_response(resp: EventResponse) -> dict[str, Any]:
    payload: dict[str, Any] = {"kind": "response", "type": type(resp).__name__}
    if isinstance(resp, ControllableInjection):
        payload["controllable"] = resp.controllable.name
        payload["value"] = resp.value
    elif isinstance(resp, ControllableNoInjection):
        payload["controllable"] = resp.controllable.name
    elif isinstance(resp, RunEndResponse):
        payload["done"] = resp.done
    return payload


def _serialize_trajectory(trajectory: Trajectory) -> list[dict[str, Any]]:
    return [
        _serialize_event(item) if isinstance(item, Event) else _serialize_response(item)
        for item in trajectory.snapshot()
    ]


def _serialize_run_result(run: RunResult, run_number: int) -> dict[str, Any]:
    return {
        "run_number": run_number,
        "evaluation": _serialize_evaluation(run.evaluation),
        "llm_usage": _serialize_llm_usage(run.llm_usage),
        "trajectory": _serialize_trajectory(run.trajectory),
    }


# ---------------------------------------------------------------------------
# Claim-level summary
# ---------------------------------------------------------------------------


def _compute_summary(tmr: ThreatModelResult) -> dict[str, Any]:
    """Aggregates over the security claim within one threat model.

    Skipped tasks (``NotApplicable``) are excluded from the score
    aggregates and counted separately. ``max_primary_score`` and
    ``mean_primary_score`` are ``None`` when no tasks were evaluated.
    """
    n_tasks = len(tmr.task_results)
    n_skipped = len(tmr.skipped_tasks)
    n_success = sum(1 for tr in tmr.task_results if tr.success)
    if tmr.task_results:
        scores = [tr.best_score.value for tr in tmr.task_results]
        max_score: float | None = max(scores)
        mean_score: float | None = sum(scores) / len(scores)
    else:
        max_score = None
        mean_score = None
    total_calls = sum(tr.llm_usage.calls for tr in tmr.task_results)
    total_cost = sum(tr.llm_usage.cost for tr in tmr.task_results)
    return {
        "n_tasks": n_tasks,
        "n_success": n_success,
        "n_skipped": n_skipped,
        "max_primary_score": max_score,
        "mean_primary_score": mean_score,
        "total_llm_usage": {"calls": total_calls, "cost": total_cost},
    }


def _serialize_task_summary(tr: TaskResult, task_file_relpath: str) -> dict[str, Any]:
    """Claim-level entry for one task — points at its detail file."""
    return {
        "task": {"goal": tr.task.goal.description},
        "file": task_file_relpath,
        "success": tr.success,
        "best_score": _serialize_score(tr.best_score),
        "llm_usage": _serialize_llm_usage(tr.llm_usage),
        "stop_reason": tr.stop_reason,
        "n_runs": len(tr.runs),
        "error": tr.error,
    }


def _serialize_full_task(
    tr: TaskResult,
    llm_config: LLMConfig | None,
    task_cost_cap_usd: float | None = None,
) -> dict[str, Any]:
    """Self-contained per-task detail (the file in the subfolder).

    Includes the threat-model context (the task's own enforced ``scope`` /
    ``read_only`` plus ``llm_config``) so a single detail file is meaningful
    in isolation, without needing the claim-level file.  In dynamic-scope mode
    these are the scope resolved for THIS task (and so may differ per file).
    When the task failed, ``error`` holds the formatted exception (type +
    message + traceback) and the last entry in ``runs`` carries the partial
    trajectory accumulated before the failure.
    """
    return {
        "version": SCHEMA_VERSION,
        "scope": _sorted_names(tr.scope),
        "read_only": _sorted_names(tr.read_only),
        "llm_config": _serialize_llm_config(llm_config),
        "task_cost_cap_usd": task_cost_cap_usd,
        "task": {"goal": tr.task.goal.description},
        "success": tr.success,
        "best_score": _serialize_score(tr.best_score),
        "best_evaluation": _serialize_evaluation(tr.best_evaluation),
        "llm_usage": _serialize_llm_usage(tr.llm_usage),
        "stop_reason": tr.stop_reason,
        "error": tr.error,
        "runs": [_serialize_run_result(r, i + 1) for i, r in enumerate(tr.runs)],
    }


def _serialize_claim_level(
    tmr: ThreatModelResult,
    task_summaries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the JSON dict for the claim-level file.

    Takes pre-built task summaries (each with the relative path to its
    detail file) so the writer can fill in paths after deciding them.
    """
    return {
        "version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "scope": _sorted_names(tmr.scope),
        "read_only": _sorted_names(tmr.read_only),
        "scope_label": tmr.scope_label,
        "llm_config": _serialize_llm_config(tmr.llm_config),
        "task_cost_cap_usd": tmr.task_cost_cap_usd,
        "summary": _compute_summary(tmr),
        "task_results": task_summaries,
        "skipped_tasks": [{"goal": t.goal.description} for t in tmr.skipped_tasks],
    }


# ---------------------------------------------------------------------------
# Atomic writer
# ---------------------------------------------------------------------------


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write *payload* as JSON to *path* atomically (temp file + rename)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=_json_fallback))
    tmp.replace(path)


def prepare_results_dir(
    results_dir: Path,
    scope: Scope,
    read_only: Scope,
    llm_config: LLMConfig | None,
    scope_label: str | None = None,
) -> Path:
    """Create *results_dir* and the per-threat-model subfolder.

    Called once at the start of a threat model, before any task runs,
    so that the layout is ready to receive incremental per-task writes.
    In dynamic-scope mode pass *scope_label* (and empty ``scope``/``read_only``)
    so the layout is named by the label.

    Raises:
        FileExistsError: if either the claim-level file or the task
            subfolder already exists. Choose a fresh ``results_dir``
            (or per-run subdirectory) to avoid collisions.

    Returns:
        The path to the per-task subfolder.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    claim_file = results_dir / _filename_for(scope, read_only, llm_config, scope_label)
    subfolder = results_dir / _subfolder_for(scope, read_only, llm_config, scope_label)
    if claim_file.exists():
        raise FileExistsError(f"Claim-level output already exists: {claim_file}")
    if subfolder.exists():
        raise FileExistsError(f"Task subfolder already exists: {subfolder}")
    subfolder.mkdir()
    return subfolder


def task_detail_filename(index: int, goal_description: str) -> str:
    """Deterministic basename for a task's detail JSON file.

    Public so callers can record the intended name in the claim-level
    summary even when :func:`write_task_detail` fails (the missing
    file then signals a write error to whoever inspects the summary).
    """
    return _task_filename(index, goal_description)


def write_task_detail(
    subfolder: Path,
    basename: str,
    tr: TaskResult,
    llm_config: LLMConfig | None,
    task_cost_cap_usd: float | None = None,
) -> None:
    """Write one task's detail file to ``subfolder/basename``.

    Called as soon as the task's :class:`TaskResult` is built (success,
    error, or budget-exhausted) so a controller that aborts mid-iteration
    leaves the completed task on disk. *basename* should come from
    :func:`task_detail_filename` so the controller can record the
    intended name even when this write raises.  The task's own enforced
    scope is read from ``tr`` (``TaskResult.scope`` / ``read_only``).

    The file is written via temp file + ``rename`` so a partial write
    cannot leave malformed JSON behind. When the task failed, the file
    contains the formatted exception traceback at the top-level
    ``error`` field and the partial trajectory as the last entry in
    ``runs`` — both are persisted *outside* the trajectory itself.
    """
    _atomic_write_json(
        subfolder / basename, _serialize_full_task(tr, llm_config, task_cost_cap_usd)
    )


def write_threat_model_result(tmr: ThreatModelResult, results_dir: Path) -> Path:
    """One-shot writer: lay out + write all detail files + write summary.

    Equivalent to the three-step incremental flow used by the
    controller, but executed synchronously for a fully-built
    :class:`ThreatModelResult`.  Useful for tests, offline conversion
    scripts, and any caller that already has the complete result in
    hand.  Returns the path to the claim-level file.
    """
    subfolder = prepare_results_dir(
        results_dir, tmr.scope, tmr.read_only, tmr.llm_config, tmr.scope_label
    )
    basenames: list[str] = []
    for i, tr in enumerate(tmr.task_results, start=1):
        basename = task_detail_filename(i, tr.task.goal.description)
        # A hand-built TaskResult may omit its per-task scope; fall back to the
        # threat-model scope so the offline detail file stays complete (the
        # controller path always populates TaskResult.scope itself).
        detail_tr = (
            tr
            if (tr.scope or tr.read_only)
            else replace(tr, scope=tmr.scope, read_only=tmr.read_only)
        )
        write_task_detail(subfolder, basename, detail_tr, tmr.llm_config, tmr.task_cost_cap_usd)
        basenames.append(basename)
    return write_claim_summary(results_dir, tmr, basenames)


def write_claim_summary(
    results_dir: Path,
    tmr: ThreatModelResult,
    task_file_basenames: list[str],
) -> Path:
    """Write the claim-level summary file. Acts as a completion marker.

    Assumes per-task detail files have already been written via
    :func:`write_task_detail`. If this file is missing for an existing
    subfolder, the run was interrupted before it could complete and the
    detail files are still the authoritative record.

    *task_file_basenames* lines up positionally with
    ``tmr.task_results`` (same length, same order).
    """
    claim_file = results_dir / _filename_for(
        tmr.scope, tmr.read_only, tmr.llm_config, tmr.scope_label
    )
    subfolder_name = _subfolder_for(tmr.scope, tmr.read_only, tmr.llm_config, tmr.scope_label)
    summaries = [
        _serialize_task_summary(tr, f"{subfolder_name}/{fname}")
        for tr, fname in zip(tmr.task_results, task_file_basenames, strict=True)
    ]
    _atomic_write_json(claim_file, _serialize_claim_level(tmr, summaries))
    return claim_file


def _json_fallback(obj: Any) -> Any:
    """Best-effort fallback for objects ``json`` doesn't know natively.

    Trajectory contents (``ObservableEvent.content``, etc.) are typed
    ``Any`` so users may put non-JSON-native objects in. Render them via
    ``repr`` rather than crash mid-write.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    return repr(obj)
