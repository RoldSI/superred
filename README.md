# SUPERRED

Modular threat-model-aware red-teaming framework for AI agents.

## Architecture

The framework is structured around three Protocol-based interfaces:

- **TargetModuleInterface** — strongest-exposure wrapper around a target AI system.
  Exposes controllables, observables, feedback channels, and a session-based
  `open_run()` for execution.
- **TaskModuleInterface** — carries the security specification (goal, evaluator,
  claims) independently of any target.  Binds to a target at runtime via
  `task.bind(target)` → `BoundTaskTargetInterface`.
- **OptimizerInterface** — attacker abstracted as an optimisation process.
  Receives controllables/observables/feedback filtered by threat model and
  produces injection values.

Security claims follow the contextual agent security framework with four
primitive property families: Task Alignment, Action Alignment, Authorized
Instruction Following, and Data Isolation.

## Installation

```bash
pip install -e .
```

For AgentDojo integration:
```bash
pip install -e ".[agentdojo]"
```

For RL attacker support:
```bash
pip install -e ".[rl]"
```

## Quick Start

```bash
# Run a sweep across all threat model profiles
superred sweep --config configs/agentdojo_sweep.yaml

# Run a single evaluation
superred run --config configs/agentdojo_single.yaml
```

## Usage (Python API)

```python
from superred.controller import Controller
from superred.core.types.threat_model import Budget, ThreatModel, SecurityDomain
from superred.optimizers.llm_mutator import LLMMutator, LLMMutatorConfig
from superred.targets.agentdojo_target import AgentDojoTarget
from superred.metrics import compute_metrics

# 1. Create target and optimizer
target = AgentDojoTarget(suite="workspace", model="gpt-4o")
optimizer = LLMMutator(LLMMutatorConfig(attacker_model="gpt-4o"))

# 2. Create a task module (binds to the target at runtime)
task = my_task_module  # implements TaskModuleInterface
bound = task.bind(target)

# 3. Define threat models
threat_models = [
    ThreatModel(
        allowed_controllables=frozenset({"user_query", "tool_response_injection"}),
        allowed_observables=frozenset({"final_output"}),
        allowed_feedback=frozenset({"attack_success"}),
        budget=Budget(max_iterations=20),
    ),
]

# 4. Run the evaluation
controller = Controller()
result = controller.run(
    target=target,
    task=task,
    optimizer=optimizer,
    threat_models=threat_models,
)

metrics = compute_metrics(result)
print(metrics.asr_by_tm)
```

## Project Structure

```
src/superred/
├── core/
│   ├── interfaces/      # Protocol-based interfaces (A, B, C)
│   │   ├── target.py    # TargetModuleInterface, TargetRunInterface
│   │   ├── task.py      # TaskModuleInterface, BoundTaskTargetInterface,
│   │   │                # EvaluatedRunInterface, SecurityClaim, OracleBundle
│   │   └── optimizer.py # OptimizerInterface
│   └── types/           # Shared data types
│       ├── threat_model.py    # SecurityDomain, ThreatModel, InterfaceSpec, ...
│       ├── trajectory.py      # EventKind, TraceEvent, Artifact
│       ├── context.py         # ActionRecord, ObservationRecord, ContextSnapshot
│       ├── security_claims.py # PropertyKind, ClaimVerdict, OracleEvidence
│       ├── task.py            # TaskDefinition, TaskFeedback
│       ├── budget.py          # HierarchicalBudget, BudgetUsage, BudgetEstimate
│       ├── controllable.py    # Controllable, ControllableValue, Modifier
│       ├── feedback.py        # EvaluationResult, FeedbackResult, Score
│       └── observable.py      # ObservableSpec, StaticObservable
├── controller.py        # Central orchestrator
├── metrics.py           # ASR, utility, cost, TTFS metrics
├── cli.py               # Click-based CLI
├── optimizers/          # Optimizer implementations
│   ├── static.py        # Static injection baseline
│   ├── llm_mutator.py   # LLM-based iterative mutation
│   ├── mcts_fuzzer.py   # MCTS-based seed selection + mutation
│   ├── meta.py          # Sequential meta-optimizer
│   └── rl_wrapper.py    # Pre-trained RL attacker wrapper
├── targets/             # Target module implementations
│   ├── agentdojo_target.py  # AgentDojo benchmark wrapper
│   └── api_target.py        # Generic HTTP API target
├── judges/              # Evaluator implementations
│   ├── function_judge.py    # Programmatic ground-truth
│   ├── llm_judge.py         # LLM-as-a-judge
│   └── regex_judge.py       # Regex-based detection
└── utils/               # Utilities
    ├── config.py         # YAML config loading
    └── serialization.py  # JSON serialisation helpers
```

## Development

```bash
pip install -e ".[dev]"
PYTHONPATH=src pytest
```
