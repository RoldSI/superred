"""Evaluation metrics computed from EvalResult.

Standard metrics:
    - ASR: Attack Success Rate
    - UA: Utility under Attack (benign task completion rate)
    - Cost/Success: Average cost per successful attack
    - TTFS: Time to First Success (iterations)
"""

from __future__ import annotations

from dataclasses import dataclass

from superred.controller import EvalResult, RunResult


@dataclass
class MetricsSummary:
    """Complete metrics for one evaluation."""

    asr_by_tm: dict[str, float]
    avg_score_by_tm: dict[str, float]
    cost_per_success_by_tm: dict[str, float]
    ttfs_by_tm: dict[str, float]
    total_cost_by_tm: dict[str, float]
    overall_asr: float = 0.0
    overall_avg_score: float = 0.0


def compute_metrics(result: EvalResult) -> MetricsSummary:
    """Compute all standard metrics from an evaluation result."""
    tm_runs: dict[str, list[RunResult]] = {}
    for tr in result.task_results:
        for run in tr.runs:
            tm_runs.setdefault(run.threat_model_name, []).append(run)

    asr: dict[str, float] = {}
    avg_score: dict[str, float] = {}
    cost_per_success: dict[str, float] = {}
    ttfs: dict[str, float] = {}
    total_cost: dict[str, float] = {}

    for tm_name, runs in tm_runs.items():
        n = len(runs)
        successes = [r for r in runs if r.success]

        asr[tm_name] = len(successes) / max(1, n)
        avg_score[tm_name] = sum(r.best_score for r in runs) / max(1, n)

        if successes:
            cost_per_success[tm_name] = sum(
                r.budget_used.cost_usd for r in successes
            ) / len(successes)
            ttfs[tm_name] = sum(r.iterations_used for r in successes) / len(successes)
        else:
            cost_per_success[tm_name] = float("inf")
            ttfs[tm_name] = float("inf")

        total_cost[tm_name] = sum(r.budget_used.cost_usd for r in runs)

    all_runs = [r for runs in tm_runs.values() for r in runs]

    return MetricsSummary(
        asr_by_tm=asr,
        avg_score_by_tm=avg_score,
        cost_per_success_by_tm=cost_per_success,
        ttfs_by_tm=ttfs,
        total_cost_by_tm=total_cost,
        overall_asr=sum(1 for r in all_runs if r.success) / max(1, len(all_runs)),
        overall_avg_score=sum(r.best_score for r in all_runs) / max(1, len(all_runs)),
    )


def format_results_table(results: dict[str, MetricsSummary]) -> str:
    """Format a comparison table: optimizers (rows) x threat models (columns)."""
    all_tms: set[str] = set()
    for ms in results.values():
        all_tms.update(ms.asr_by_tm.keys())
    tms = sorted(all_tms)

    lines = []
    header = f"{'Optimizer':<30}" + "".join(f"{tm:>15}" for tm in tms)
    lines.append(header)
    lines.append("-" * len(header))

    for opt_name, ms in results.items():
        row = f"{opt_name:<30}"
        for tm in tms:
            asr_val = ms.asr_by_tm.get(tm, 0)
            row += f"{asr_val:>14.1%} "
        lines.append(row)

    return "\n".join(lines)
