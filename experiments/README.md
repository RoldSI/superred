# SUPERRED Empirical Validation Experiments

Experiments to validate two core hypotheses from the paper:

- **H1**: ASR increases as threat model surface widens (user\_only < user\_external < user\_external\_internal)
- **H2**: A composed meta-optimizer (MCTS + LLM Mutator) outperforms either component alone at matched budget

## Prerequisites

```bash
pip install -e .
export OPENAI_API_KEY="sk-..."
```

## Experiments

| # | Name | Hypothesis | Config(s) | Command |
|---|------|-----------|-----------|---------|
| 1 | Threat Model Sweep | H1 | `exp1_tm_sweep.yaml` | `superred sweep -c configs/experiments/exp1_tm_sweep.yaml` |
| 2 | Optimizer Comparison | H3 | `exp2_*.yaml` | See runner script |
| 3 | Composition Ablation | H2 | `exp3_*.yaml` | See runner script |
| 4 | Cross-Suite Portability | -- | `exp4_*.yaml` | See runner script |
| 5 | Framework Overhead | -- | N/A | `python scripts/baseline_direct_agentdojo.py` |

### Experiment 1: Threat Model Surface Area vs ASR

Runs MCTS Fuzzer on 20 AgentDojo `workspace` tasks under all threat model profiles.
Tests whether ASR increases as more injection surfaces are exposed.

### Experiment 2: Optimizer Comparison

Runs Static, LLM Mutator, MCTS Fuzzer, and Meta optimizers on the same 20 tasks
under `user_external` threat model with the same budget (25 iterations).

### Experiment 3: Composition Ablation

Runs MCTS-only, LLM-only, and Meta(MCTS->LLM) on 20 tasks with matched budget
(25 iterations each). Tests whether composition beats individual components.

### Experiment 4: Cross-Suite Portability

Runs the MCTS Fuzzer on `banking`, `travel`, and `slack` suites to demonstrate
the framework generalizes with zero code changes.

### Experiment 5: Framework Overhead Baseline

Runs the same static injection directly through agentdojo's Python API (bypassing
SUPERRED) and compares ASR to Experiment 2's static result.

## Running

### All experiments

```bash
./scripts/run_experiments.sh
```

### Selective experiments

```bash
./scripts/run_experiments.sh 1        # experiment 1 only
./scripts/run_experiments.sh 1 3      # experiments 1 and 3
./scripts/run_experiments.sh --dry-run # print commands without running
```

### Individual experiments

```bash
superred sweep -c configs/experiments/exp1_tm_sweep.yaml
superred run -c configs/experiments/exp2_mcts.yaml
python scripts/baseline_direct_agentdojo.py
```

## Analysis

```bash
python scripts/analyze_results.py                  # print tables for all experiments
python scripts/analyze_results.py --exp 1 2        # specific experiments
python scripts/analyze_results.py --csv             # export to results/all_results.csv
python scripts/analyze_results.py --plot            # generate plots (needs matplotlib)
```

## Comparing results

```bash
superred compare -r results/exp2_static.json -r results/exp2_mcts.json -r results/exp2_meta.json
```

## Output

Results are saved to `results/`:

```
results/
├── exp1_tm_sweep.json
├── exp2_static.json
├── exp2_llm.json
├── exp2_mcts.json
├── exp2_meta.json
├── exp3_mcts.json
├── exp3_llm.json
├── exp3_meta.json
├── exp4_banking.json
├── exp4_travel.json
├── exp4_slack.json
├── exp5_baseline.json
├── all_results.csv
├── logs/
│   └── *.log
└── plots/
    ├── exp1_tm_sweep.png
    ├── exp2_optimizer_comparison.png
    └── exp3_composition_ablation.png
```

## Time and Cost Estimates

| Experiment | Runs | Est. Time | Est. Cost (gpt-4o-mini) |
|-----------|------|-----------|------------------------|
| Exp 1 | 60 | ~2h | ~$2-4 |
| Exp 2 | 80 | ~2.5h | ~$3-5 |
| Exp 3 | 60 | ~2h | ~$2-4 |
| Exp 4 | 60 | ~2h | ~$2-4 |
| Exp 5 | 20 | ~30min | ~$0.50 |
| **Total** | **280** | **~9h** | **~$10-17** |
