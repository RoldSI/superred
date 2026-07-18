"""Live progress reporting for the Controller.

The Controller narrates one threat model's run through a small observer
seam, :class:`ProgressReporter`.  It calls the reporter at each lifecycle
point (threat-model start, task start, each run/iteration, task complete,
task skipped, diagnostics, threat-model end) and never renders anything
itself.  This keeps ``controller.py`` free of any terminal concern and
lets the same run drive a rich live dashboard, plain lines, or nothing.

Three built-in reporters:

* :class:`NullReporter` — no-ops (used when reporting is disabled).
* :class:`PlainReporter` — line-oriented output with no ANSI canvas; the
  fallback for non-TTY / ``NO_COLOR`` / dumb terminals / CI / pipes and
  the target of tests.  Its start banner and end summary reproduce the
  content of the controller's old ``_print_summary``.
* :class:`Dashboard` (in this module) — a shared ``rich`` live canvas that
  coordinates one or many concurrently-gathered Controllers into a single
  terminal view.  One ``Dashboard`` owns one ``rich`` ``Console`` and one
  ``Live``; each Controller gets a *lane* (one row) via
  :meth:`Dashboard.reporter_for`.

Threading contract (hard): every :class:`ProgressReporter` method is
called on the asyncio loop thread and must not block or await.  A blocking
method serializes otherwise-concurrent tasks and starves sibling lanes.
Reporters that touch shared state from other threads (the logging bridge
feeding off-loop diagnostics) marshal onto the loop thread themselves; see
:class:`Dashboard`.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import os
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import IO, Literal, Protocol, TextIO, runtime_checkable

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Severity of a diagnostic surfaced to the reporter (mirrors logging levels).
DiagnosticLevel = Literal["info", "warning", "error"]

# Why a task's run loop ended.  Kept as a bare str alias here (rather than
# imported from ``controller``) so this module never imports the controller —
# the dependency runs one way only (controller imports reporting).
StopReason = str


# ---------------------------------------------------------------------------
# Lifecycle payloads (all frozen, kw_only — cheap immutable value objects)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class ThreatModelContext:
    """The invariant identity + parameters of one threat model.

    Delivered once at :meth:`ProgressReporter.on_threat_model_start` and
    used to render the header (experiment parameters) and to name the
    lane.  All fields are human-facing display values, not live objects.

    Attributes:
        label: Short experiment label (the lane title / persistence stem).
        attacker: Optimizer display name (the attacker).
        target: Target display name (the system under test).
        claim: Security-claim display name.
        model: Attacker LLM model id, or ``None`` for a non-LLM optimizer.
        scope: Read & write scope tag names (display).
        read_only: Read-only tag names (display); empty for a read & write run.
        scope_label: Dynamic-scope run label, or ``None`` in static mode.
        task_cost_cap_usd: Attacker per-task cost cap in USD, or ``None``.
        max_runs_per_task: Safety cap on runs per task.
        include_feedback: Whether evaluation feedback reaches the optimizer.
        concurrency: Max tasks run in parallel within this threat model.
        n_tasks: Number of tasks in the claim, or ``None`` if not yet known.
    """

    label: str
    attacker: str
    target: str
    claim: str
    model: str | None
    scope: tuple[str, ...] = ()
    read_only: tuple[str, ...] = ()
    scope_label: str | None = None
    task_cost_cap_usd: float | None = None
    max_runs_per_task: int = 0
    include_feedback: bool = True
    concurrency: int = 1
    n_tasks: int | None = None

    @property
    def scope_desc(self) -> str:
        """One-line human description of the scope (matches the old summary)."""
        if self.scope_label is not None:
            return f"{self.scope_label} (per-task)"
        names = ", ".join(self.scope) or "(none)"
        if self.read_only:
            return f"[{names}] read_only=[{', '.join(self.read_only)}]"
        return f"[{names}]"


@dataclass(frozen=True, kw_only=True)
class TaskStartEvent:
    """A task has started running (after scope resolve + target create)."""

    task_index: int
    goal: str


@dataclass(frozen=True, kw_only=True)
class RunCompleteEvent:
    """One optimizer run/iteration finished (or failed mid-run).

    Attributes:
        task_index: 1-based task index within the claim.
        goal: The task goal (display).
        run_number: 1-based run index within the task.
        primary_score: The run's primary score (``0.0`` on a failed run).
        success: Whether this run achieved the adversarial goal.
        evaluated: ``True`` if the score came from the evaluator; ``False``
            for the synthetic zero on an error/budget path.
        errored: ``True`` if the run raised mid-execution.
        done: Whether the optimizer signalled it wants to stop.
        run_cost_delta_usd: Cost of THIS run only (a delta, never the
            cumulative snapshot — summing deltas across runs is correct).
        cumulative_cost_usd: Attacker cumulative cost for the task so far.
    """

    task_index: int
    goal: str
    run_number: int
    primary_score: float
    success: bool
    evaluated: bool
    errored: bool
    done: bool
    run_cost_delta_usd: float
    cumulative_cost_usd: float


@dataclass(frozen=True, kw_only=True)
class TaskCompleteEvent:
    """A task's run loop ended (success, failure, error, or budget)."""

    task_index: int
    goal: str
    success: bool
    stop_reason: StopReason
    best_score: float
    n_runs: int
    cost_usd: float
    calls: int = 0
    error: str | None = None


@dataclass(frozen=True, kw_only=True)
class TaskSkippedEvent:
    """A task was skipped (NotApplicable / empty resolved scope)."""

    task_index: int
    goal: str
    reason: str = ""


@dataclass(frozen=True, kw_only=True)
class DiagnosticEvent:
    """A diagnostic (log record) surfaced for the side pane / per-task log.

    Attributes:
        label: The experiment label of the emitting Controller.
        task_index: 1-based task index the record belongs to, or ``None``
            for an experiment-level / off-loop (unattributed) record.
        level: Severity.
        message: The formatted message.
        logger_name: Source logger name (for downstream filtering).
    """

    label: str
    task_index: int | None
    level: DiagnosticLevel
    message: str
    logger_name: str = ""


@dataclass(frozen=True, kw_only=True)
class ThreatModelEndEvent:
    """The threat model finished; carries the final aggregate for the summary.

    Attributes:
        context: The same context delivered at start (for the final header).
        n_tasks: Evaluated task count (excludes skipped).
        n_success: Tasks that achieved the goal.
        n_completed: Tasks that ran to a verdict (done + max_runs + budget);
            the ASR denominator (excludes error and skipped).
        n_error: Tasks abandoned with ``stop_reason == "error"``.
        n_budget_exhausted: Tasks stopped by the cost cap.
        n_skipped: Tasks skipped (NotApplicable).
        asr: ``n_success / n_completed``, or ``None`` when no completed task.
        max_primary_score: Max best-score over evaluated tasks, or ``None``.
        mean_primary_score: Mean best-score over evaluated tasks, or ``None``.
        total_calls: Total attacker LLM calls across the threat model.
        total_cost_usd: Total attacker LLM cost across the threat model.
        duration_s: Wall-clock seconds for the threat model, or ``None``.
    """

    context: ThreatModelContext
    n_tasks: int
    n_success: int
    n_completed: int
    n_error: int
    n_budget_exhausted: int
    n_skipped: int
    asr: float | None
    max_primary_score: float | None
    mean_primary_score: float | None
    total_calls: int
    total_cost_usd: float
    duration_s: float | None = None


# ---------------------------------------------------------------------------
# Observer protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ProgressReporter(Protocol):
    """Synchronous, non-blocking observer of one threat model's progress.

    Every method is called on the asyncio loop thread and must return
    promptly (no ``await``, no blocking I/O).  A custom reporter that needs
    to do slow work should hand it off to another thread/queue.
    """

    def on_threat_model_start(self, ctx: ThreatModelContext) -> None: ...
    def on_task_start(self, ev: TaskStartEvent) -> None: ...
    def on_run_complete(self, ev: RunCompleteEvent) -> None: ...
    def on_task_complete(self, ev: TaskCompleteEvent) -> None: ...
    def on_task_skipped(self, ev: TaskSkippedEvent) -> None: ...
    def on_diagnostic(self, ev: DiagnosticEvent) -> None: ...
    def on_threat_model_end(self, ev: ThreatModelEndEvent) -> None: ...


class NullReporter:
    """A reporter that does nothing (used when reporting is disabled)."""

    def on_threat_model_start(self, ctx: ThreatModelContext) -> None:
        return None

    def on_task_start(self, ev: TaskStartEvent) -> None:
        return None

    def on_run_complete(self, ev: RunCompleteEvent) -> None:
        return None

    def on_task_complete(self, ev: TaskCompleteEvent) -> None:
        return None

    def on_task_skipped(self, ev: TaskSkippedEvent) -> None:
        return None

    def on_diagnostic(self, ev: DiagnosticEvent) -> None:
        return None

    def on_threat_model_end(self, ev: ThreatModelEndEvent) -> None:
        return None


# ---------------------------------------------------------------------------
# Plain (non-TTY) reporter
# ---------------------------------------------------------------------------

_STATUS = {
    "done": "OK",
    "max_runs": "FAIL",
    "budget_exhausted": "BUDGET",
    "error": "ERROR",
}


class PlainReporter:
    """Line-oriented reporter with no ANSI canvas.

    Emits a start banner, one line per task completion / skip, and a final
    summary block.  Per-run events are silent by default (a 100-run task
    would otherwise flood the log).  Error-level diagnostics go to stderr.
    The start banner and end summary intentionally mirror the content of
    the controller's former ``_print_summary`` so nothing is lost when the
    canvas is unavailable.

    Args:
        file: Stream for progress lines (default ``sys.stdout``).
        err: Stream for error diagnostics (default ``sys.stderr``).
        show_runs: If ``True``, print a line per run/iteration too.
    """

    def __init__(
        self,
        file: IO[str] | None = None,
        err: IO[str] | None = None,
        show_runs: bool = False,
    ) -> None:
        self._file: IO[str] = file if file is not None else sys.stdout
        self._err: IO[str] = err if err is not None else sys.stderr
        self._show_runs = show_runs

    def _print(self, line: str = "") -> None:
        print(line, file=self._file)

    def on_threat_model_start(self, ctx: ThreatModelContext) -> None:
        model = ctx.model or "(no LLM)"
        n = ctx.n_tasks if ctx.n_tasks is not None else "?"
        budget = (
            "unlimited" if ctx.task_cost_cap_usd is None else f"${ctx.task_cost_cap_usd:g}/task"
        )
        self._print("\n" + "=" * 64)
        self._print(f"Threat model: scope={ctx.scope_desc} model={model}")
        self._print(
            f"  attacker={ctx.attacker} target={ctx.target} claim={ctx.claim} "
            f"tasks={n} concurrency={ctx.concurrency} budget={budget}"
        )
        self._print("=" * 64)

    def on_task_start(self, ev: TaskStartEvent) -> None:
        return None

    def on_run_complete(self, ev: RunCompleteEvent) -> None:
        if not self._show_runs:
            return None
        self._print(
            f"  · task {ev.task_index} run {ev.run_number}: "
            f"score={ev.primary_score:.4f} success={ev.success} done={ev.done}"
        )

    def on_task_complete(self, ev: TaskCompleteEvent) -> None:
        tag = _STATUS.get(ev.stop_reason, "OK" if ev.success else "FAIL")
        if ev.success:
            tag = "OK"
        self._print(
            f"  [{tag}] {ev.goal}"
            f"  score={ev.best_score:.4f} runs={ev.n_runs} cost=${ev.cost_usd:.6f}"
        )

    def on_task_skipped(self, ev: TaskSkippedEvent) -> None:
        self._print(f"  [SKIP] {ev.goal}")

    def on_diagnostic(self, ev: DiagnosticEvent) -> None:
        if ev.level == "error":
            where = f"task {ev.task_index}" if ev.task_index is not None else "exp"
            print(f"[{where}] {ev.message}", file=self._err)

    def on_threat_model_end(self, ev: ThreatModelEndEvent) -> None:
        asr = "n/a" if ev.asr is None else f"{ev.asr:.1%}"
        best = "n/a" if ev.max_primary_score is None else f"{ev.max_primary_score:.4f}"
        self._print("\n" + "-" * 64)
        self._print(
            f"  Overall: {ev.n_success}/{ev.n_completed} completed tasks succeeded (ASR {asr})"
        )
        if ev.n_error or ev.n_budget_exhausted or ev.n_skipped:
            self._print(
                f"  Errors: {ev.n_error}  Budget-exhausted: {ev.n_budget_exhausted}  "
                f"Skipped: {ev.n_skipped}"
            )
        self._print(f"  Highest score: {best}")
        self._print(
            f"  Attacker LLM: {ev.total_calls} calls, ${ev.total_cost_usd:.6f}"
            + ("" if ev.duration_s is None else f"  ({ev.duration_s:.1f}s)")
        )
        self._print("=" * 64 + "\n")


# ---------------------------------------------------------------------------
# Terminal capability detection (graceful degradation)
# ---------------------------------------------------------------------------


def _env_forces_plain(env: dict[str, str] | None = None) -> bool:
    """Whether the environment forces plain (no live canvas) output.

    Explicit env overrides so a pty-capturing CI runner (which may report a
    terminal) still gets plain, log-friendly output rather than a canvas
    plus redirected stdout sprayed into a log file.
    """
    e = os.environ if env is None else env
    if e.get("SUPERRED_NO_DASHBOARD"):
        return True
    if e.get("CI"):
        return True
    # NO_COLOR alone only strips color; combined with a dumb terminal it is a
    # strong signal there is no usable canvas.
    if e.get("NO_COLOR") and e.get("TERM", "") == "dumb":
        return True
    if e.get("TERM", "") == "dumb":
        return True
    return False


def _stream_is_tty(stream: TextIO | None = None) -> bool:
    """Best-effort TTY check for *stream* (default stdout)."""
    s = stream if stream is not None else sys.stdout
    try:
        return bool(s.isatty())
    except Exception:
        return False


def should_use_plain(
    stream: TextIO | None = None,
    env: dict[str, str] | None = None,
) -> bool:
    """Decide whether to fall back to :class:`PlainReporter`.

    Plain is used when the stream is not a TTY, or the environment forces it
    (CI / ``SUPERRED_NO_DASHBOARD`` / dumb terminal).  The rich canvas is
    used only on a real interactive terminal.
    """
    return _env_forces_plain(env) or not _stream_is_tty(stream)


# ---------------------------------------------------------------------------
# Shared live dashboard (rich)
# ---------------------------------------------------------------------------

# Coalesce repaints to at most one per this interval (trailing-edge, so the
# last event before the run goes quiet is always painted).
_REFRESH_INTERVAL_S = 0.1
_DIAG_MAXLEN = 400

# Process-wide single-``Live`` guard.  rich allows only one ``Live`` per
# terminal; a second silently stomps the first.  At most one Dashboard holds
# the canvas; any other degrades its lanes to plain output.
_ACTIVE_LIVE_LOCK = threading.Lock()
_ACTIVE_LIVE: Live | None = None

_DEFAULT_DASHBOARD_LOCK = threading.Lock()
_DEFAULT_DASHBOARD: Dashboard | None = None


def _fmt_dur(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def _bar(fraction: float, width: int = 12) -> str:
    fraction = 0.0 if fraction < 0 else (1.0 if fraction > 1 else fraction)
    filled = int(round(fraction * width))
    return "█" * filled + "░" * (width - filled)


@dataclass
class _LaneState:
    """Mutable per-Controller display state (mutated only on the loop thread)."""

    ctx: ThreatModelContext
    started_at: float
    in_flight: int = 0
    n_terminal: int = 0  # tasks reaching any terminal state (incl. skipped)
    n_success: int = 0
    n_completed: int = 0  # done + max_runs + budget_exhausted (ASR denominator)
    n_error: int = 0
    n_budget: int = 0
    n_skipped: int = 0
    n_runs: int = 0
    total_calls: int = 0
    total_cost: float = 0.0
    best_score: float = 0.0
    end_ev: ThreatModelEndEvent | None = None


class Dashboard:
    """A shared ``rich`` live canvas coordinating one or many Controllers.

    One ``Dashboard`` owns exactly one ``rich`` ``Console`` and one ``Live``.
    Each Controller is given a *lane* (one row) via :meth:`reporter_for`.
    Multiple concurrently-gathered Controllers therefore render into a single
    terminal view, never fighting over the screen.

    Threading: all lane callbacks arrive on the asyncio loop thread and mutate
    lane state directly.  Off-loop diagnostics (the logging bridge) are
    marshalled onto the loop thread via ``call_soon_threadsafe`` before they
    touch any shared state, so there is no cross-thread mutation and no lock on
    the display state.  The only lock is the process-wide single-``Live`` guard.

    Args:
        console: A ``rich`` ``Console`` to render into (default: a fresh one).
        redirect: Redirect stray ``stdout``/``stderr`` through the live canvas
            so a stray ``print`` cannot corrupt it (default ``True``; tests
            pass ``False``).
    """

    def __init__(self, console: Console | None = None, redirect: bool = True) -> None:
        self._console_arg = console
        self._redirect = redirect
        self._console: Console | None = None
        self._live: Live | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread_id: int | None = None
        self._lanes: dict[str, _LaneState] = {}
        self._diagnostics: deque[DiagnosticEvent] = deque(maxlen=_DIAG_MAXLEN)
        self._diag_lock = threading.Lock()
        self._active_lanes = 0
        self._flush_scheduled = False
        self._canvas_ok = False
        self._started = False
        self._stopped = False
        self._live_stopped = False
        self._atexit_registered = False

    # -- Public API --------------------------------------------------------

    def reporter_for(self, label: str) -> ProgressReporter:
        """Mint a reporter bound to one lane (row) of this dashboard."""
        return _RichLane(self, label)

    def __enter__(self) -> Dashboard:
        return self

    def __exit__(self, *exc: object) -> None:
        self._force_stop()

    # -- Lifecycle (loop thread) ------------------------------------------

    def _ensure_started(self) -> None:
        if self._started:
            return
        self._started = True
        try:
            self._loop = asyncio.get_running_loop()
            self._loop_thread_id = threading.get_ident()
        except RuntimeError:
            self._loop = None
        self._console = self._console_arg or Console()
        global _ACTIVE_LIVE
        with _ACTIVE_LIVE_LOCK:
            if _ACTIVE_LIVE is None and self._loop is not None:
                self._live = Live(
                    self._render(),
                    console=self._console,
                    auto_refresh=False,
                    transient=False,
                    redirect_stdout=self._redirect,
                    redirect_stderr=self._redirect,
                )
                self._live.start()
                _ACTIVE_LIVE = self._live
                self._canvas_ok = True
            else:
                # Another Live is active (or no loop): degrade to plain lanes.
                self._canvas_ok = False
        if not self._atexit_registered:
            atexit.register(self._force_stop)
            self._atexit_registered = True

    def _lane_start(self, label: str, ctx: ThreatModelContext) -> None:
        self._lanes[label] = _LaneState(ctx=ctx, started_at=time.monotonic())
        self._active_lanes += 1
        self._request_refresh()

    def _lane_end(self, label: str, ev: ThreatModelEndEvent) -> None:
        lane = self._lanes.get(label)
        if lane is not None:
            lane.end_ev = ev
        self._active_lanes -= 1
        if self._active_lanes <= 0:
            self._shutdown()
        else:
            self._request_refresh()

    def _shutdown(self) -> None:
        """Last lane finished: paint the final frame, stop, print the summary.

        The render is best-effort and MUST NOT skip the ``Live.stop()`` — a
        render exception that left the canvas running would strand the terminal
        in alt-screen / hidden-cursor state.  Stopping the ``Live`` is delegated
        to :meth:`_stop_live` (idempotent), which the ``atexit``/``__exit__``
        safety net also calls, so the terminal is always restored.
        """
        if self._stopped:
            return
        self._stopped = True
        try:
            if self._live is not None and self._canvas_ok:
                self._live.update(self._render(), refresh=True)
        except Exception:  # pragma: no cover - a render error must not skip the stop
            pass
        self._stop_live()
        if self._console is not None:
            try:
                self._console.print(self._render_final_summary())
            except Exception:  # pragma: no cover - final summary print is best-effort
                pass

    def _stop_live(self) -> None:
        """Stop the ``Live`` and release the process-wide canvas (idempotent)."""
        global _ACTIVE_LIVE
        if self._live is None or self._live_stopped:
            return
        self._live_stopped = True
        try:
            with _ACTIVE_LIVE_LOCK:
                self._live.stop()
                if _ACTIVE_LIVE is self._live:
                    _ACTIVE_LIVE = None
        except Exception:  # pragma: no cover - teardown must never raise
            pass

    def _force_stop(self) -> None:
        """Belt-and-suspenders teardown (atexit / context exit)."""
        self._stop_live()

    # -- Metric updates (loop thread) -------------------------------------

    def _task_start(self, label: str, ev: TaskStartEvent) -> None:
        lane = self._lanes.get(label)
        if lane is not None:
            lane.in_flight += 1
        self._request_refresh()

    def _run_complete(self, label: str, ev: RunCompleteEvent) -> None:
        lane = self._lanes.get(label)
        if lane is not None:
            lane.n_runs += 1
        self._request_refresh()

    def _task_complete(self, label: str, ev: TaskCompleteEvent) -> None:
        lane = self._lanes.get(label)
        if lane is None:
            return
        lane.in_flight = max(0, lane.in_flight - 1)
        lane.n_terminal += 1
        lane.total_cost += ev.cost_usd
        lane.total_calls += ev.calls
        lane.best_score = max(lane.best_score, ev.best_score)
        completed = ev.stop_reason in ("done", "max_runs", "budget_exhausted")
        # Count a success only among completed tasks so the lane ASR
        # (n_success / n_completed) stays in [0, 1]: a task can be success=True
        # yet stop_reason="error" (goal met, then reset_ephemeral_state failed).
        if ev.success and completed:
            lane.n_success += 1
        if ev.stop_reason in ("done", "max_runs"):
            lane.n_completed += 1
        elif ev.stop_reason == "budget_exhausted":
            lane.n_completed += 1
            lane.n_budget += 1
        elif ev.stop_reason == "error":
            lane.n_error += 1
        self._request_refresh()

    def _task_skipped(self, label: str, ev: TaskSkippedEvent) -> None:
        lane = self._lanes.get(label)
        if lane is not None:
            lane.n_terminal += 1
            lane.n_skipped += 1
        self._request_refresh()

    # -- Diagnostics (any thread) -----------------------------------------

    def submit_diagnostic(self, ev: DiagnosticEvent) -> None:
        """Deliver a diagnostic, marshalling onto the loop thread if needed."""
        if self._loop is None or threading.get_ident() == self._loop_thread_id:
            self._apply_diagnostic(ev)
        else:
            self._loop.call_soon_threadsafe(self._apply_diagnostic, ev)

    def _apply_diagnostic(self, ev: DiagnosticEvent) -> None:
        with self._diag_lock:
            self._diagnostics.append(ev)
        self._request_refresh()

    # -- Rendering (loop thread) ------------------------------------------

    def _request_refresh(self) -> None:
        if not self._canvas_ok or self._live is None or self._loop is None:
            return
        if self._flush_scheduled:
            return
        self._flush_scheduled = True
        self._loop.call_later(_REFRESH_INTERVAL_S, self._flush_refresh)

    def _flush_refresh(self) -> None:
        self._flush_scheduled = False
        if self._live is not None and self._canvas_ok and not self._stopped:
            self._live.update(self._render(), refresh=True)

    def _render(self) -> Layout:
        layout = Layout()
        layout.split_row(
            Layout(name="main", ratio=2),
            Layout(self._render_side(), name="side", ratio=1, minimum_size=28),
        )
        layout["main"].split_column(
            Layout(self._render_header(), name="header", size=self._header_size()),
            Layout(self._render_body(), name="body"),
        )
        return layout

    def _header_size(self) -> int:
        return 11 if len(self._lanes) == 1 else 5

    def _render_header(self) -> Panel:
        if len(self._lanes) == 1:
            (lane,) = self._lanes.values()
            ctx = lane.ctx
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style="bold cyan", justify="right")
            grid.add_column()
            budget = (
                "unlimited"
                if ctx.task_cost_cap_usd is None
                else f"${ctx.task_cost_cap_usd:g} / task"
            )
            grid.add_row("attacker", ctx.attacker)
            grid.add_row("target", ctx.target)
            grid.add_row("claim", ctx.claim)
            grid.add_row("model", ctx.model or "(no LLM)")
            grid.add_row("scope", ctx.scope_desc)
            grid.add_row("budget", budget)
            n_tasks = ctx.n_tasks if ctx.n_tasks is not None else "?"
            elapsed = _fmt_dur(time.monotonic() - lane.started_at)
            grid.add_row(
                "run",
                f"{n_tasks} tasks · concurrency {ctx.concurrency} · elapsed {elapsed}",
            )
            return Panel(grid, title="[bold]superred[/bold]", border_style="cyan")
        # Multi-lane sweep: a compact aggregate line.
        total_tasks = sum(la.ctx.n_tasks or 0 for la in self._lanes.values())
        done = sum(la.n_terminal for la in self._lanes.values())
        succ = sum(la.n_success for la in self._lanes.values())
        comp = sum(la.n_completed for la in self._lanes.values())
        cost = sum(la.total_cost for la in self._lanes.values())
        asr = f"{(succ / comp):.1%}" if comp else "n/a"
        text = Text.from_markup(
            f"[bold]{len(self._lanes)}[/bold] threat models · "
            f"[bold]{done}/{total_tasks}[/bold] tasks · "
            f"ASR [bold]{asr}[/bold] · "
            f"[green]{succ}[/green] success · "
            f"cost [bold]${cost:.4f}[/bold]"
        )
        return Panel(text, title="[bold]superred[/bold]", border_style="cyan")

    def _render_body(self) -> Panel:
        table = Table(expand=True, pad_edge=False, box=None)
        table.add_column("threat model", style="bold", ratio=3, no_wrap=True)
        table.add_column("progress", ratio=3, no_wrap=True)
        table.add_column("ASR", justify="right", ratio=1)
        table.add_column("ok/fail/err/skip", justify="center", ratio=2, no_wrap=True)
        table.add_column("live", justify="right", ratio=1)
        table.add_column("cost", justify="right", ratio=1)
        for label, lane in self._lanes.items():
            n = lane.ctx.n_tasks or 0
            frac = (lane.n_terminal / n) if n else (1.0 if lane.end_ev else 0.0)
            asr = f"{(lane.n_success / lane.n_completed):.0%}" if lane.n_completed else "-"
            fail = lane.n_completed - lane.n_success
            counts = (
                f"[green]{lane.n_success}[/green]/[yellow]{fail}[/yellow]/"
                f"[red]{lane.n_error}[/red]/[dim]{lane.n_skipped}[/dim]"
            )
            done_mark = "[green]✓[/green] " if lane.end_ev is not None else ""
            table.add_row(
                f"{done_mark}{label}",
                f"[cyan]{_bar(frac)}[/cyan] {lane.n_terminal}/{n}",
                asr,
                counts,
                str(lane.in_flight) if lane.in_flight else "[dim]0[/dim]",
                f"${lane.total_cost:.4f}",
            )
        return Panel(table, title="tasks", border_style="blue")

    def _render_side(self) -> Panel:
        with self._diag_lock:
            items = list(self._diagnostics)[-40:]
        style = {"info": "dim", "warning": "yellow", "error": "bold red"}
        body = Text()
        for ev in items:
            where = f"t{ev.task_index}" if ev.task_index is not None else "exp"
            body.append(f"{where} ", style="dim")
            body.append(ev.message + "\n", style=style.get(ev.level, "dim"))
        if not items:
            body = Text("(no diagnostics)", style="dim")
        return Panel(body, title="diagnostics / errors", border_style="grey37")

    def _render_final_summary(self) -> Table:
        table = Table(title="superred · final results", expand=True)
        table.add_column("threat model", style="bold")
        table.add_column("ASR", justify="right")
        table.add_column("success", justify="right")
        table.add_column("error", justify="right")
        table.add_column("skip", justify="right")
        table.add_column("best", justify="right")
        table.add_column("cost", justify="right")
        for label, lane in self._lanes.items():
            ev = lane.end_ev
            asr = "n/a" if ev is None or ev.asr is None else f"{ev.asr:.1%}"
            best = (
                "n/a"
                if ev is None or ev.max_primary_score is None
                else f"{ev.max_primary_score:.4f}"
            )
            table.add_row(
                label,
                asr,
                f"{lane.n_success}/{lane.n_completed}",
                str(lane.n_error),
                str(lane.n_skipped),
                best,
                f"${lane.total_cost:.4f}",
            )
        return table


class _RichLane:
    """A :class:`ProgressReporter` bound to one lane of a :class:`Dashboard`.

    When the dashboard could not acquire the live canvas (another ``Live`` is
    active, or the environment is non-interactive), every call is delegated to
    a :class:`PlainReporter` writing to the shared console, so a mixed-usage
    sweep degrades gracefully rather than crashing.
    """

    def __init__(self, dashboard: Dashboard, label: str) -> None:
        self._d = dashboard
        self._label = label
        self._plain: PlainReporter | None = None

    def _plain_reporter(self) -> PlainReporter:
        if self._plain is None:
            file = self._d._console.file if self._d._console is not None else None
            self._plain = PlainReporter(file=file)
        return self._plain

    def on_threat_model_start(self, ctx: ThreatModelContext) -> None:
        self._d._ensure_started()
        if not self._d._canvas_ok:
            self._plain_reporter().on_threat_model_start(ctx)
            return
        self._d._lane_start(self._label, ctx)

    def on_task_start(self, ev: TaskStartEvent) -> None:
        if not self._d._canvas_ok:
            return self._plain_reporter().on_task_start(ev)
        self._d._task_start(self._label, ev)

    def on_run_complete(self, ev: RunCompleteEvent) -> None:
        if not self._d._canvas_ok:
            return self._plain_reporter().on_run_complete(ev)
        self._d._run_complete(self._label, ev)

    def on_task_complete(self, ev: TaskCompleteEvent) -> None:
        if not self._d._canvas_ok:
            return self._plain_reporter().on_task_complete(ev)
        self._d._task_complete(self._label, ev)

    def on_task_skipped(self, ev: TaskSkippedEvent) -> None:
        if not self._d._canvas_ok:
            return self._plain_reporter().on_task_skipped(ev)
        self._d._task_skipped(self._label, ev)

    def on_diagnostic(self, ev: DiagnosticEvent) -> None:
        if not self._d._canvas_ok:
            return self._plain_reporter().on_diagnostic(ev)
        self._d.submit_diagnostic(ev)

    def on_threat_model_end(self, ev: ThreatModelEndEvent) -> None:
        if not self._d._canvas_ok:
            return self._plain_reporter().on_threat_model_end(ev)
        self._d._lane_end(self._label, ev)


# ---------------------------------------------------------------------------
# Reporter resolution
# ---------------------------------------------------------------------------


def get_default_dashboard() -> Dashboard:
    """Return the process-global :class:`Dashboard`, re-arming it if spent.

    A ``Dashboard`` is single-use: once its last lane ends it stops the ``Live``
    and marks itself stopped.  Sequential sweeps (one ``Controller.run()`` after
    another, a supported pattern) must each get a fresh canvas, so a stopped
    default is replaced here rather than silently reused (which would swallow
    all output for every threat model after the first).
    """
    global _DEFAULT_DASHBOARD
    with _DEFAULT_DASHBOARD_LOCK:
        if _DEFAULT_DASHBOARD is None or _DEFAULT_DASHBOARD._stopped:
            _DEFAULT_DASHBOARD = Dashboard()
        return _DEFAULT_DASHBOARD


def resolve_reporter(
    label: str,
    *,
    report: bool | Literal["auto"] = "auto",
    reporter: ProgressReporter | None = None,
    stream: TextIO | None = None,
) -> ProgressReporter:
    """Resolve the reporter for a Controller.

    * an explicit *reporter* wins;
    * ``report=False`` disables reporting (:class:`NullReporter`);
    * otherwise reporting is on: a live :class:`Dashboard` lane on a real
      terminal, or a :class:`PlainReporter` when the stream is not a TTY / the
      environment forces plain output.
    """
    if reporter is not None:
        return reporter
    if report is False:
        return NullReporter()
    if should_use_plain(stream):
        return PlainReporter()
    return get_default_dashboard().reporter_for(label)


def _reset_for_tests() -> None:
    """Reset process-global dashboard state (test helper only)."""
    global _DEFAULT_DASHBOARD, _ACTIVE_LIVE
    with _DEFAULT_DASHBOARD_LOCK:
        _DEFAULT_DASHBOARD = None
    with _ACTIVE_LIVE_LOCK:
        _ACTIVE_LIVE = None


# ---------------------------------------------------------------------------
# Logging bridge: Python logging -> reporter + per-task sink
# ---------------------------------------------------------------------------

# Set per task by the controller (label, 1-based index).  Contextvars propagate
# across ``await`` within an asyncio task, so a log record emitted anywhere in a
# task's coroutine chain reads the correct attribution.  Records from worker
# threads that did not inherit the contextvar read ``None`` (experiment-level).
current_task: ContextVar[tuple[str, int] | None] = ContextVar("superred_current_task", default=None)

DiagnosticSink = Callable[[DiagnosticEvent], None]


def _level_name(levelno: int) -> DiagnosticLevel:
    if levelno >= logging.ERROR:
        return "error"
    if levelno >= logging.WARNING:
        return "warning"
    return "info"


class LoggingBridge(logging.Handler):
    """A ``logging.Handler`` that forwards records to a reporter + optional sink.

    Attribution comes from the :data:`current_task` contextvar.  A record whose
    context belongs to a *different* controller (different label) is ignored, so
    concurrently-gathered controllers each handle only their own tasks' records;
    unattributed records (``None`` context, e.g. worker threads) are handled at
    experiment scope (``task_index=None``).
    """

    def __init__(
        self, label: str, reporter: ProgressReporter, sink: DiagnosticSink | None = None
    ) -> None:
        super().__init__()
        self._label = label
        self._reporter = reporter
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            ref = current_task.get()
            if ref is not None and ref[0] != self._label:
                return
            index = ref[1] if ref is not None else None
            ev = DiagnosticEvent(
                label=self._label,
                task_index=index,
                level=_level_name(record.levelno),
                message=record.getMessage(),
                logger_name=record.name,
            )
            self._reporter.on_diagnostic(ev)
            if self._sink is not None:
                self._sink(ev)
        except Exception:  # pragma: no cover - a logging handler must never raise into user code
            pass
