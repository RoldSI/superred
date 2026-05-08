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

All files are written atomically (temp file + ``rename``). Per-task
detail files are written first; the claim-level file lands last and
acts as a completion marker for the threat model.

``LLMConfig`` fields ``api_key`` and ``api_base`` are explicitly
excluded from serialization. Trajectory contents are not scrubbed for
secrets — the caller is responsible for not putting credentials into
log/observable payloads.
"""

from __future__ import annotations

import json
import re
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


def filename_for(scope: Scope, llm_config: LLMConfig | None) -> str:
    """Deterministic filename for the (scope, llm_config) claim-level file.

    Format: ``{sanitized_tag1.sanitized_tag2...}__{sanitized_model}.json``
    with tags sorted alphabetically. ``llm_config is None`` becomes
    ``no-llm``.
    """
    scope_part = ".".join(_sanitize_segment(t.name) for t in sorted(scope, key=lambda t: t.name))
    model_part = _sanitize_segment(llm_config.model) if llm_config is not None else "no-llm"
    return f"{scope_part}__{model_part}.json"


def _subfolder_for(scope: Scope, llm_config: LLMConfig | None) -> str:
    """Deterministic name of the per-task subfolder for a threat model.

    Same stem as :func:`filename_for` minus the ``.json`` suffix.
    """
    return filename_for(scope, llm_config).removesuffix(".json")


def task_filename(index: int, goal_description: str) -> str:
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
    return {"model": cfg.model, "max_cost": cfg.max_cost}


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
    }


def _serialize_full_task(tr: TaskResult, tmr: ThreatModelResult) -> dict[str, Any]:
    """Self-contained per-task detail (the file in the subfolder).

    Includes the threat-model context (scope, llm_config) so a single
    detail file is meaningful in isolation, without needing the
    claim-level file.
    """
    return {
        "version": SCHEMA_VERSION,
        "scope": sorted(t.name for t in tmr.scope),
        "llm_config": _serialize_llm_config(tmr.llm_config),
        "task": {"goal": tr.task.goal.description},
        "success": tr.success,
        "best_score": _serialize_score(tr.best_score),
        "best_evaluation": _serialize_evaluation(tr.best_evaluation),
        "llm_usage": _serialize_llm_usage(tr.llm_usage),
        "stop_reason": tr.stop_reason,
        "runs": [_serialize_run_result(r, i + 1) for i, r in enumerate(tr.runs)],
    }


def serialize_claim_level(
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
        "scope": sorted(t.name for t in tmr.scope),
        "llm_config": _serialize_llm_config(tmr.llm_config),
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


def write_threat_model_result(tmr: ThreatModelResult, results_dir: Path) -> Path:
    """Persist *tmr* under *results_dir* using the subfolder layout.

    Per-task detail files are written into
    ``{results_dir}/{subfolder}/`` first; the claim-level file lands
    last and acts as a completion marker. Each individual file is
    written via temp file + ``rename`` so a partial write can never
    leave a malformed JSON behind.

    Raises:
        FileExistsError: if either the claim-level file or the task
            subfolder already exists. Choose a fresh ``results_dir``
            (or per-run subdirectory) to avoid collisions.

    Returns:
        The path to the written claim-level file.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    claim_file = results_dir / filename_for(tmr.scope, tmr.llm_config)
    subfolder_name = _subfolder_for(tmr.scope, tmr.llm_config)
    subfolder = results_dir / subfolder_name

    if claim_file.exists():
        raise FileExistsError(f"Claim-level output already exists: {claim_file}")
    if subfolder.exists():
        raise FileExistsError(f"Task subfolder already exists: {subfolder}")

    subfolder.mkdir(parents=True)

    task_summaries: list[dict[str, Any]] = []
    for index, tr in enumerate(tmr.task_results, start=1):
        fname = task_filename(index, tr.task.goal.description)
        detail_path = subfolder / fname
        _atomic_write_json(detail_path, _serialize_full_task(tr, tmr))
        rel_path = f"{subfolder_name}/{fname}"
        task_summaries.append(_serialize_task_summary(tr, rel_path))

    _atomic_write_json(claim_file, serialize_claim_level(tmr, task_summaries))
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
