#!/usr/bin/env bash
#
# Run all SUPERRED empirical validation experiments.
#
# Usage:
#   ./scripts/run_experiments.sh              # run all experiments
#   ./scripts/run_experiments.sh 1            # run only experiment 1
#   ./scripts/run_experiments.sh 1 2          # run experiments 1 and 2
#   ./scripts/run_experiments.sh --dry-run    # print commands without running
#
# Prerequisites:
#   - OPENAI_API_KEY must be set in the environment
#   - superred must be installed (pip install -e .)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_DIR="$PROJECT_DIR/configs/experiments"
RESULTS_DIR="$PROJECT_DIR/results"
LOG_DIR="$PROJECT_DIR/results/logs"

mkdir -p "$RESULTS_DIR" "$LOG_DIR"

DRY_RUN=false
EXPERIMENTS=()

for arg in "$@"; do
    if [ "$arg" = "--dry-run" ]; then
        DRY_RUN=true
    else
        EXPERIMENTS+=("$arg")
    fi
done

if [ ${#EXPERIMENTS[@]} -eq 0 ]; then
    EXPERIMENTS=(1 2 3 4)
fi

if [ "$DRY_RUN" = false ] && [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "ERROR: OPENAI_API_KEY is not set." >&2
    exit 1
fi

run_cmd() {
    local label="$1"
    local cmd="$2"
    local logfile="$LOG_DIR/${label}.log"

    echo ""
    echo "========================================"
    echo "  $label"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================"

    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] $cmd"
        return 0
    fi

    echo "  Log: $logfile"
    echo "  Running..."

    local start_ts
    start_ts=$(date +%s)

    if eval "$cmd" > "$logfile" 2>&1; then
        local end_ts
        end_ts=$(date +%s)
        local elapsed=$(( end_ts - start_ts ))
        echo "  DONE in ${elapsed}s"
    else
        local end_ts
        end_ts=$(date +%s)
        local elapsed=$(( end_ts - start_ts ))
        echo "  FAILED after ${elapsed}s (see $logfile)" >&2
    fi
}

for exp in "${EXPERIMENTS[@]}"; do
    case "$exp" in
        1)
            echo ""
            echo "########################################"
            echo "# EXPERIMENT 1: Threat Model Sweep (H1)"
            echo "########################################"
            run_cmd "exp1_tm_sweep" \
                "superred sweep -c $CONFIG_DIR/exp1_tm_sweep.yaml"
            ;;
        2)
            echo ""
            echo "########################################"
            echo "# EXPERIMENT 2: Optimizer Comparison (H3)"
            echo "########################################"
            run_cmd "exp2_static" \
                "superred run -c $CONFIG_DIR/exp2_static.yaml"
            run_cmd "exp2_llm" \
                "superred run -c $CONFIG_DIR/exp2_llm.yaml"
            run_cmd "exp2_mcts" \
                "superred run -c $CONFIG_DIR/exp2_mcts.yaml"
            run_cmd "exp2_meta" \
                "superred run -c $CONFIG_DIR/exp2_meta.yaml"
            ;;
        3)
            echo ""
            echo "#############################################"
            echo "# EXPERIMENT 3: Composition Ablation (H2)"
            echo "#############################################"
            run_cmd "exp3_mcts" \
                "superred run -c $CONFIG_DIR/exp3_mcts.yaml"
            run_cmd "exp3_llm" \
                "superred run -c $CONFIG_DIR/exp3_llm.yaml"
            run_cmd "exp3_meta" \
                "superred run -c $CONFIG_DIR/exp3_meta.yaml"
            ;;
        4)
            echo ""
            echo "#############################################"
            echo "# EXPERIMENT 4: Cross-Suite Portability"
            echo "#############################################"
            run_cmd "exp4_banking" \
                "superred run -c $CONFIG_DIR/exp4_banking.yaml"
            run_cmd "exp4_travel" \
                "superred run -c $CONFIG_DIR/exp4_travel.yaml"
            run_cmd "exp4_slack" \
                "superred run -c $CONFIG_DIR/exp4_slack.yaml"
            ;;
        *)
            echo "Unknown experiment: $exp (valid: 1, 2, 3, 4)" >&2
            ;;
    esac
done

echo ""
echo "========================================"
echo "  All requested experiments complete."
echo "  Results: $RESULTS_DIR/"
echo "  Logs:    $LOG_DIR/"
echo "========================================"

if [ "$DRY_RUN" = false ]; then
    echo ""
    echo "Run analysis:"
    echo "  python3 scripts/analyze_results.py"
fi
