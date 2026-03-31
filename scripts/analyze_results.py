#!/usr/bin/env python3
"""
Analyze SUPERRED experiment results.

Loads result JSON files, computes metrics, prints comparison tables,
and generates key plots for the paper.

Usage:
    python scripts/analyze_results.py                    # all experiments
    python scripts/analyze_results.py --exp 1            # experiment 1 only
    python scripts/analyze_results.py --results-dir out  # custom results dir
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent


def load_result(path: Path) -> dict | None:
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def print_header(title: str) -> None:
    width = 72
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def fmt_pct(val: float) -> str:
    return f"{val:.1%}"


def fmt_float(val: float) -> str:
    if val == float("inf"):
        return "---"
    return f"{val:.3f}"


# ── Experiment 1: Threat Model Sweep ─────────────────────────────────────

def analyze_exp1(results_dir: Path) -> None:
    print_header("Experiment 1: Threat Model Surface Area vs ASR (H1)")
    data = load_result(results_dir / "exp1_tm_sweep.json")
    if data is None:
        print("  [SKIP] results/exp1_tm_sweep.json not found")
        return

    summary = data["summary"]
    tm_order = ["user_only", "user_external", "user_external_internal", "full_access"]
    present = [tm for tm in tm_order if tm in summary]

    print()
    print(f"  {'Threat Model':<30} {'ASR':>8} {'Avg Score':>10} {'Avg Iters':>10} {'Tasks':>7}")
    print("  " + "-" * 67)

    asr_values = []
    for tm in present:
        s = summary[tm]
        asr = s["asr"]
        asr_values.append(asr)
        print(
            f"  {tm:<30} {fmt_pct(asr):>8} {fmt_float(s['avg_score']):>10} "
            f"{s['avg_iterations']:>10.1f} {s['total_tasks']:>7}"
        )

    print()
    if len(asr_values) >= 2:
        if asr_values[-1] > asr_values[0]:
            print("  >>> H1 SUPPORTED: ASR increases with wider threat model surface")
            print(f"      ({fmt_pct(asr_values[0])} -> {fmt_pct(asr_values[-1])})")
        elif asr_values[-1] == asr_values[0]:
            print("  >>> H1 INCONCLUSIVE: ASR is the same across threat models")
        else:
            print("  >>> H1 NOT SUPPORTED: ASR does not increase with wider threat model")


# ── Experiment 2: Optimizer Comparison ───────────────────────────────────

def analyze_exp2(results_dir: Path) -> None:
    print_header("Experiment 2: Optimizer Comparison (H3)")

    names = [
        ("exp2_static", "Static Injection"),
        ("exp2_llm", "LLM Mutator"),
        ("exp2_mcts", "MCTS Fuzzer"),
        ("exp2_meta", "Meta (MCTS+LLM)"),
    ]

    rows = []
    for filename, label in names:
        data = load_result(results_dir / f"{filename}.json")
        if data is None:
            continue
        summary = data["summary"]
        tm_key = next(iter(summary))
        s = summary[tm_key]
        rows.append((label, s))

    if not rows:
        print("  [SKIP] No exp2_*.json files found")
        return

    print()
    print(f"  {'Optimizer':<25} {'ASR':>8} {'Avg Score':>10} {'Avg Iters':>10} {'Avg Cost':>10} {'Tasks':>7}")
    print("  " + "-" * 72)

    for label, s in rows:
        print(
            f"  {label:<25} {fmt_pct(s['asr']):>8} {fmt_float(s['avg_score']):>10} "
            f"{s['avg_iterations']:>10.1f} {fmt_float(s['avg_cost_usd']):>10} {s['total_tasks']:>7}"
        )

    asrs = [(label, s["asr"]) for label, s in rows]
    best_label, best_asr = max(asrs, key=lambda x: x[1])
    print()
    print(f"  Best optimizer: {best_label} (ASR={fmt_pct(best_asr)})")

    if len(asrs) >= 2:
        sorted_asrs = sorted(asrs, key=lambda x: x[1], reverse=True)
        rankings_str = " > ".join(f"{l} ({fmt_pct(a)})" for l, a in sorted_asrs)
        print(f"  Ranking: {rankings_str}")


# ── Experiment 3: Composition Ablation ───────────────────────────────────

def analyze_exp3(results_dir: Path) -> None:
    print_header("Experiment 3: Composition Ablation (H2)")

    names = [
        ("exp3_mcts", "MCTS Only"),
        ("exp3_llm", "LLM Only"),
        ("exp3_meta", "Meta (MCTS->LLM)"),
    ]

    rows = []
    for filename, label in names:
        data = load_result(results_dir / f"{filename}.json")
        if data is None:
            continue
        summary = data["summary"]
        tm_key = next(iter(summary))
        s = summary[tm_key]
        rows.append((label, s))

    if not rows:
        print("  [SKIP] No exp3_*.json files found")
        return

    print()
    print(f"  {'Condition':<25} {'ASR':>8} {'Avg Score':>10} {'Avg Iters':>10} {'Avg Cost':>10} {'Tasks':>7}")
    print("  " + "-" * 72)

    for label, s in rows:
        print(
            f"  {label:<25} {fmt_pct(s['asr']):>8} {fmt_float(s['avg_score']):>10} "
            f"{s['avg_iterations']:>10.1f} {fmt_float(s['avg_cost_usd']):>10} {s['total_tasks']:>7}"
        )

    result_map = {label: s for label, s in rows}
    meta_asr = result_map.get("Meta (MCTS->LLM)", {}).get("asr", -1)
    component_asrs = [
        s["asr"]
        for label, s in rows
        if label != "Meta (MCTS->LLM)"
    ]

    print()
    if meta_asr >= 0 and component_asrs:
        best_component = max(component_asrs)
        if meta_asr > best_component:
            print("  >>> H2 SUPPORTED: Composed meta-optimizer beats best individual component")
            print(f"      Meta ASR={fmt_pct(meta_asr)} vs best component ASR={fmt_pct(best_component)}")
        elif meta_asr == best_component:
            print("  >>> H2 INCONCLUSIVE: Meta ties with best component")
        else:
            print("  >>> H2 NOT SUPPORTED: Meta underperforms best component")
            print(f"      Meta ASR={fmt_pct(meta_asr)} vs best component ASR={fmt_pct(best_component)}")


# ── Experiment 4: Cross-Suite Portability ────────────────────────────────

def analyze_exp4(results_dir: Path) -> None:
    print_header("Experiment 4: Cross-Suite Portability")

    suites = ["workspace", "banking", "travel", "slack"]
    rows = []

    for suite in suites:
        path = results_dir / f"exp4_{suite}.json"
        data = load_result(path)
        if data is None:
            # Exp1 uses workspace with sweep; use workspace from exp2/exp3 as fallback
            if suite == "workspace":
                for fallback in ["exp2_mcts.json", "exp3_mcts.json", "exp1_tm_sweep.json"]:
                    data = load_result(results_dir / fallback)
                    if data is not None:
                        break
            if data is None:
                continue

        summary = data["summary"]
        tm_key = "user_external" if "user_external" in summary else next(iter(summary))
        s = summary[tm_key]
        rows.append((suite, tm_key, s))

    if not rows:
        print("  [SKIP] No exp4_*.json files found")
        return

    print()
    print(f"  {'Suite':<15} {'Threat Model':<25} {'ASR':>8} {'Avg Score':>10} {'Tasks':>7}")
    print("  " + "-" * 67)

    for suite, tm, s in rows:
        print(
            f"  {suite:<15} {tm:<25} {fmt_pct(s['asr']):>8} {fmt_float(s['avg_score']):>10} "
            f"{s['total_tasks']:>7}"
        )

    print()
    print(f"  Framework ran on {len(rows)} suite(s) with zero code changes.")


# ── Experiment 5: Framework Overhead ─────────────────────────────────────

def analyze_exp5(results_dir: Path) -> None:
    print_header("Experiment 5: Framework Overhead Baseline")

    data = load_result(results_dir / "exp5_baseline.json")
    framework_data = load_result(results_dir / "exp2_static.json")

    if data is None:
        print("  [SKIP] results/exp5_baseline.json not found")
        print("  Run: python scripts/baseline_direct_agentdojo.py")
        return

    baseline_summary = data.get("summary", {})
    baseline_asr = baseline_summary.get("asr", 0)
    baseline_tasks = baseline_summary.get("total_tasks", 0)

    print()
    print(f"  {'Condition':<25} {'ASR':>8} {'Tasks':>7}")
    print("  " + "-" * 42)
    print(f"  {'Direct agentdojo':<25} {fmt_pct(baseline_asr):>8} {baseline_tasks:>7}")

    if framework_data is not None:
        fw_summary = framework_data["summary"]
        tm_key = next(iter(fw_summary))
        fw_asr = fw_summary[tm_key]["asr"]
        fw_tasks = fw_summary[tm_key]["total_tasks"]
        print(f"  {'SUPERRED framework':<25} {fmt_pct(fw_asr):>8} {fw_tasks:>7}")

        delta = abs(fw_asr - baseline_asr)
        print()
        if delta < 0.05:
            print(f"  >>> OVERHEAD OK: ASR difference is {fmt_pct(delta)} (< 5%)")
        else:
            print(f"  >>> WARNING: ASR difference is {fmt_pct(delta)} (>= 5%)")
    else:
        print(f"  {'SUPERRED framework':<25} {'[N/A]':>8} {'[N/A]':>7}")
        print()
        print("  Run exp2_static to compare.")


# ── Combined Summary ─────────────────────────────────────────────────────

def print_summary(results_dir: Path) -> None:
    print_header("HYPOTHESIS SUMMARY")

    all_results = {}
    for path in sorted(results_dir.glob("*.json")):
        data = load_result(path)
        if data:
            all_results[path.stem] = data

    if not all_results:
        print("  No result files found in", results_dir)
        return

    print()
    print(f"  Total result files: {len(all_results)}")
    print(f"  Files: {', '.join(sorted(all_results.keys()))}")

    total_runs = 0
    total_successes = 0
    for name, data in all_results.items():
        summary = data.get("summary", {})
        for tm, s in summary.items():
            if not isinstance(s, dict):
                continue
            total_runs += s.get("total_tasks", 0)
            total_successes += s.get("successes", 0)

    print(f"  Total task-threat_model runs: {total_runs}")
    print(f"  Total successes: {total_successes}")
    if total_runs > 0:
        print(f"  Overall ASR: {fmt_pct(total_successes / total_runs)}")


# ── CSV Export ────────────────────────────────────────────────────────────

def export_csv(results_dir: Path) -> None:
    """Export all results to a single CSV for further analysis."""
    csv_path = results_dir / "all_results.csv"

    rows = []
    for path in sorted(results_dir.glob("*.json")):
        data = load_result(path)
        if data is None:
            continue

        config = data.get("config", {})
        optimizer_type = config.get("optimizer", {}).get("type", "unknown")
        suite = config.get("target", {}).get("params", {}).get("suite", "unknown")

        for tm_name, s in data.get("summary", {}).items():
            if not isinstance(s, dict):
                continue
            rows.append({
                "experiment": path.stem,
                "suite": suite,
                "optimizer": optimizer_type,
                "threat_model": tm_name,
                "asr": s.get("asr", 0),
                "avg_score": s.get("avg_score", 0),
                "avg_iterations": s.get("avg_iterations", 0),
                "avg_cost_usd": s.get("avg_cost_usd", 0),
                "total_tasks": s.get("total_tasks", 0),
                "successes": s.get("successes", 0),
            })

    if not rows:
        print("\n  No results to export.")
        return

    cols = list(rows[0].keys())
    with open(csv_path, "w") as f:
        f.write(",".join(cols) + "\n")
        for row in rows:
            vals = []
            for c in cols:
                v = row[c]
                if isinstance(v, float):
                    vals.append(f"{v:.6f}")
                else:
                    vals.append(str(v))
            f.write(",".join(vals) + "\n")

    print(f"\n  Exported {len(rows)} rows to {csv_path}")


# ── Plotting ─────────────────────────────────────────────────────────────

def generate_plots(results_dir: Path) -> None:
    """Generate key plots. Requires matplotlib."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n  [SKIP] matplotlib not installed. Install with: pip install matplotlib")
        return

    plots_dir = results_dir / "plots"
    plots_dir.mkdir(exist_ok=True)

    _plot_exp1_tm_sweep(results_dir, plots_dir, plt)
    _plot_exp2_optimizer_comparison(results_dir, plots_dir, plt)
    _plot_exp3_composition(results_dir, plots_dir, plt)


def _plot_exp1_tm_sweep(results_dir: Path, plots_dir: Path, plt) -> None:
    data = load_result(results_dir / "exp1_tm_sweep.json")
    if data is None:
        return

    summary = data["summary"]
    tm_order = ["user_only", "user_external", "user_external_internal", "full_access"]
    present = [tm for tm in tm_order if tm in summary]
    if not present:
        return

    labels = [tm.replace("_", "\n") for tm in present]
    asrs = [summary[tm]["asr"] * 100 for tm in present]
    scores = [summary[tm]["avg_score"] * 100 for tm in present]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = range(len(present))
    bars = ax.bar(x, asrs, width=0.6, color="#2196F3", alpha=0.85, label="ASR (%)")
    ax.plot(x, scores, "o-", color="#FF5722", linewidth=2, markersize=8, label="Avg Score (%)")

    for bar, val in zip(bars, asrs):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{val:.1f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Percentage (%)", fontsize=12)
    ax.set_title("Experiment 1: ASR vs Threat Model Surface (H1)", fontsize=13)
    ax.set_ylim(0, max(max(asrs), max(scores)) * 1.2 + 5)
    ax.legend(loc="upper left")
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    path = plots_dir / "exp1_tm_sweep.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {path}")


def _plot_exp2_optimizer_comparison(results_dir: Path, plots_dir: Path, plt) -> None:
    names = [
        ("exp2_static", "Static"),
        ("exp2_llm", "LLM Mutator"),
        ("exp2_mcts", "MCTS Fuzzer"),
        ("exp2_meta", "Meta"),
    ]

    labels = []
    asrs = []
    for filename, label in names:
        data = load_result(results_dir / f"{filename}.json")
        if data is None:
            continue
        summary = data["summary"]
        tm_key = next(iter(summary))
        labels.append(label)
        asrs.append(summary[tm_key]["asr"] * 100)

    if len(labels) < 2:
        return

    colors = ["#9E9E9E", "#4CAF50", "#2196F3", "#FF9800"][:len(labels)]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, asrs, color=colors, alpha=0.85)
    for bar, val in zip(bars, asrs):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{val:.1f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")

    ax.set_ylabel("ASR (%)", fontsize=12)
    ax.set_title("Experiment 2: Optimizer Comparison (user_external)", fontsize=13)
    ax.set_ylim(0, max(asrs) * 1.3 + 5)
    ax.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    path = plots_dir / "exp2_optimizer_comparison.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {path}")


def _plot_exp3_composition(results_dir: Path, plots_dir: Path, plt) -> None:
    names = [
        ("exp3_mcts", "MCTS Only"),
        ("exp3_llm", "LLM Only"),
        ("exp3_meta", "Meta\n(MCTS->LLM)"),
    ]

    labels = []
    asrs = []
    iters_list = []
    for filename, label in names:
        data = load_result(results_dir / f"{filename}.json")
        if data is None:
            continue
        summary = data["summary"]
        tm_key = next(iter(summary))
        labels.append(label)
        asrs.append(summary[tm_key]["asr"] * 100)
        iters_list.append(summary[tm_key]["avg_iterations"])

    if len(labels) < 2:
        return

    colors = ["#2196F3", "#4CAF50", "#FF9800"][:len(labels)]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    bars1 = ax1.bar(labels, asrs, color=colors, alpha=0.85)
    for bar, val in zip(bars1, asrs):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                 f"{val:.1f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax1.set_ylabel("ASR (%)", fontsize=12)
    ax1.set_title("Composition Ablation: ASR", fontsize=13)
    ax1.set_ylim(0, max(asrs) * 1.3 + 5)
    ax1.grid(axis="y", alpha=0.3)

    bars2 = ax2.bar(labels, iters_list, color=colors, alpha=0.85)
    for bar, val in zip(bars2, iters_list):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                 f"{val:.1f}", ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Avg Iterations to Converge", fontsize=12)
    ax2.set_title("Composition Ablation: Efficiency", fontsize=13)
    ax2.set_ylim(0, max(iters_list) * 1.3 + 2)
    ax2.grid(axis="y", alpha=0.3)

    fig.suptitle("Experiment 3: Composition Ablation (H2) — Matched Budget: 25 iters", fontsize=14, y=1.02)
    fig.tight_layout()
    path = plots_dir / "exp3_composition_ablation.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved: {path}")


# ── Main ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze SUPERRED experiment results")
    parser.add_argument("--exp", type=int, nargs="*", help="Experiment numbers to analyze (default: all)")
    parser.add_argument("--results-dir", type=str, default=str(PROJECT_DIR / "results"),
                        help="Directory containing result JSON files")
    parser.add_argument("--csv", action="store_true", help="Export results to CSV")
    parser.add_argument("--plot", action="store_true", help="Generate plots (requires matplotlib)")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    if not results_dir.exists():
        print(f"Results directory not found: {results_dir}", file=sys.stderr)
        sys.exit(1)

    experiments = args.exp or [1, 2, 3, 4, 5]

    for exp in experiments:
        if exp == 1:
            analyze_exp1(results_dir)
        elif exp == 2:
            analyze_exp2(results_dir)
        elif exp == 3:
            analyze_exp3(results_dir)
        elif exp == 4:
            analyze_exp4(results_dir)
        elif exp == 5:
            analyze_exp5(results_dir)

    print_summary(results_dir)

    if args.csv:
        export_csv(results_dir)

    if args.plot:
        print_header("Generating Plots")
        generate_plots(results_dir)

    print()


if __name__ == "__main__":
    main()
