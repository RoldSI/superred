"""Persistence helpers for ``ThreatModelResult`` artifacts.

Module-private. Imported only by :mod:`superred.core.controller`. No
public re-exports — opting into persistence is a single keyword argument
on the :class:`Controller` constructor.

Wire format: one JSON file per completed threat model, written
atomically (temp file + ``rename``) so the on-disk artifact is either
absent or fully formed. ``LLMConfig`` fields ``api_key`` and
``api_base`` are explicitly excluded from serialization. Trajectory
contents are not scrubbed for secrets — the caller is responsible for
not putting credentials into log/observable payloads.
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
    from superred.core.controller import (
        ControllerConfig,
        RunResult,
        TaskResult,
        ThreatModelResult,
    )


SCHEMA_VERSION = 1

_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9_-]")


def _sanitize_segment(s: str) -> str:
    """Replace any character outside ``[A-Za-z0-9_-]`` with ``_``."""
    return _SAFE_SEGMENT_RE.sub("_", s)


def filename_for(scope: Scope, llm_config: LLMConfig | None) -> str:
    """Deterministic filename for a (scope, llm_config) threat model.

    Format: ``{sanitized_tag1.sanitized_tag2...}__{sanitized_model}.json``
    with tags sorted alphabetically. ``llm_config is None`` becomes
    ``no-llm``.
    """
    scope_part = ".".join(_sanitize_segment(t.name) for t in sorted(scope, key=lambda t: t.name))
    model_part = _sanitize_segment(llm_config.model) if llm_config is not None else "no-llm"
    return f"{scope_part}__{model_part}.json"


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


def _serialize_controller_config(cc: ControllerConfig) -> dict[str, Any]:
    return {"max_runs_per_task": cc.max_runs_per_task, "include_feedback": cc.include_feedback}


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


def _serialize_task_result(tr: TaskResult) -> dict[str, Any]:
    return {
        "task": {"goal": tr.task.goal.description},
        "success": tr.success,
        "best_score": _serialize_score(tr.best_score),
        "best_evaluation": _serialize_evaluation(tr.best_evaluation),
        "llm_usage": _serialize_llm_usage(tr.llm_usage),
        "stop_reason": tr.stop_reason,
        "runs": [_serialize_run_result(r, i + 1) for i, r in enumerate(tr.runs)],
    }


def serialize_threat_model_result(tmr: ThreatModelResult) -> dict[str, Any]:
    """Build the JSON-serializable dict for a single threat model."""
    return {
        "version": SCHEMA_VERSION,
        "completed_at": datetime.now(UTC).isoformat(),
        "scope": sorted(t.name for t in tmr.scope),
        "llm_config": _serialize_llm_config(tmr.llm_config),
        "controller_config": _serialize_controller_config(tmr.controller_config),
        "task_results": [_serialize_task_result(t) for t in tmr.task_results],
        "skipped_tasks": [{"goal": t.goal.description} for t in tmr.skipped_tasks],
    }


# ---------------------------------------------------------------------------
# Atomic writer
# ---------------------------------------------------------------------------


def write_threat_model_result(tmr: ThreatModelResult, results_dir: Path) -> Path:
    """Persist *tmr* to ``{results_dir}/{filename_for(...)}`` atomically.

    The directory is created if needed. The write is atomic: data lands
    in a sibling ``.tmp`` file first, then ``rename``\\ s into place. If
    the destination file already exists, raises :class:`FileExistsError`
    rather than overwriting silently.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    target = results_dir / filename_for(tmr.scope, tmr.llm_config)
    if target.exists():
        raise FileExistsError(f"Threat-model output already exists: {target}")
    payload = serialize_threat_model_result(tmr)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=_json_fallback))
    tmp.replace(target)
    return target


def _json_fallback(obj: Any) -> Any:
    """Best-effort fallback for objects ``json`` doesn't know natively.

    Trajectory contents (``ObservableEvent.content``, etc.) are typed
    ``Any`` so users may put non-JSON-native objects in. Render them via
    ``repr`` rather than crash mid-write.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    return repr(obj)
