# Running Evaluations

The Controller wires everything together and runs the evaluation. This guide covers construction, execution, and interpreting results.

## Controller Construction

```python
from superred.core.controller import Controller
from superred.core.types.llm import LLMConfig

controller = Controller(
    optimizer=optimizer,
    target=target,
    security_claim=claim,
    security_domain_tag=scope_tag,
    llm_config=LLMConfig(             # required — LLM access for optimizer
        model="gpt-4o-mini",
        api_base="https://api.openai.com",
        api_key="sk-...",
        max_cost=5.00,                # USD budget limit (optional)
    ),
    max_runs_per_task=100,  # safety limit, default 100
)
```

| Parameter | Description |
|-----------|-------------|
| `optimizer` | The attacker (Optimizer instance) |
| `target` | The AI system under test (Target instance) |
| `security_claim` | The collection of tasks to evaluate |
| `security_domain_tag` | Which security scope to test from |
| `max_runs_per_task` | Safety limit on runs per task (min 1) |
| `llm_config` | LLM access for the optimizer (`LLMConfig`) — required |

## Running

```python
result = await controller.run()
```

Or from a script:

```python
import asyncio

async def main():
    controller = Controller(...)
    result = await controller.run()

asyncio.run(main())
```

The Controller:
1. Iterates each task in the security claim
2. Configures the target for the task
3. Runs the optimizer loop until done or max_runs
4. Evaluates each run
5. Prints a summary to stdout
6. Calls teardown on both optimizer and target (even on errors)
7. Returns a `ControllerResult`

## Interpreting Results

### ControllerResult

```python
result = await controller.run()

# All task results
for tr in result.task_results:
    print(f"Task: {tr.task.goal.description}")
    print(f"  Success: {tr.success}")
    print(f"  Best score: {tr.best_score.value}")
    print(f"  Runs: {len(tr.runs)}")

# Tasks that were skipped (raised NotApplicable)
for task in result.skipped_tasks:
    print(f"Skipped: {task.goal.description}")
```

### TaskResult

```python
tr = result.task_results[0]

tr.task            # the Task that was evaluated
tr.success         # True if ANY run achieved the goal
tr.best_score      # Score with the highest value across all runs
tr.best_evaluation # the EvaluationResult that produced the best score
tr.runs            # list[RunResult], one per optimizer run
tr.llm_usage       # LLMUsage — total optimizer LLM usage for this task
```

### RunResult

```python
for run in tr.runs:
    run.trajectory     # the Trajectory for this run
    run.evaluation     # the EvaluationResult for this run
    run.llm_usage      # LLMUsage — cumulative optimizer LLM usage after this run

    # Inspect the trajectory
    entries = run.trajectory.snapshot()
    for entry in entries:
        if isinstance(entry, LogEvent):
            print(f"  [{entry.label}]: {entry.content}")

    # Check the evaluation
    print(f"  Score: {run.evaluation.primary_score.value}")
    print(f"  Success: {run.evaluation.success}")
    print(f"  Rationale: {run.evaluation.rationale}")
```

### Events in the Trajectory

The Controller records all events and responses directly in the trajectory as `Event | EventResponse` objects. There is no separate event log. To inspect events for a run, use `isinstance` checks:

```python
from superred.core.types.event import (
    ControllableInjection,
    ControllablePreCallEvent,
    FeedbackEvent,
    LogEvent,
)

for run in tr.runs:
    entries = run.trajectory.snapshot()
    for entry in entries:
        if isinstance(entry, ControllablePreCallEvent):
            print(f"Event: {type(entry).__name__}")
        elif isinstance(entry, ControllableInjection):
            print(f"Injection: {entry.value}")
        elif isinstance(entry, LogEvent):
            print(f"Log [{entry.label}]: {entry.content}")
        elif isinstance(entry, FeedbackEvent):
            print(f"Feedback: {entry.evaluation.primary_score.value}")
```

Controllable events and their responses are recorded in the trajectory. Lifecycle events (`RunStartEvent`, `RunEndEvent`) flow through the channel only and are NOT stored in the trajectory.

## Multiple Tasks

The Controller evaluates each task in order:

```python
claim = SecurityClaim.from_tasks([
    SecretExtractionTask(secret="ALPHA"),
    PromptInjectionTask(),
    DataExfiltrationTask(),
])

controller = Controller(
    optimizer=optimizer,
    target=target,
    security_claim=claim,
    security_domain_tag=user_tag,
)
result = await controller.run()

# Each task gets its own TaskResult
assert len(result.task_results) == 3  # (minus any skipped)
```

For each task, the optimizer is re-initialized with the task's goal. The target is re-configured. The run loop is independent per task.

## Error Handling

The Controller is exception-safe:

- **Target.run() raises**: The error propagates. Teardown still runs.
- **Task.evaluate() raises**: The error propagates. Teardown still runs.
- **Optimizer.on_event() raises**: The exception is propagated to the controller via the channel. Teardown still runs.
- **Task raises NotApplicable**: The task is skipped and added to `result.skipped_tasks`.

```python
try:
    result = await controller.run()
except Exception as e:
    print(f"Evaluation failed: {e}")
    # teardown() was still called on both optimizer and target
```

## Choosing the Security Domain Scope

The `security_domain_tag` parameter controls what the optimizer can see and control:

```python
# Test from the user's perspective — optimizer controls user input only
controller = Controller(..., security_domain_tag=user_input_tag)

# Test from a broader scope — optimizer controls all external surfaces
controller = Controller(..., security_domain_tag=external_tag)

# Test everything — optimizer controls all injection points
controller = Controller(..., security_domain_tag=root_tag)
```

See [Security Domains](07-security-domains.md) for details.

## Complete Example

```python
import asyncio
import os
from dotenv import load_dotenv

from superred.core.controller import Controller
from superred.core.types.llm import LLMConfig
from simple_chat_target import SimpleChatTarget, USER_INPUT_TAG
from trivial_prompt_optimizer import TrivialPromptOptimizer
from secret_leak_claim import secret_leak_claim


async def main():
    load_dotenv()

    api_base = os.environ["LITELLM_API_BASE"]
    api_key = os.environ["LITELLM_API_KEY"]

    target = SimpleChatTarget(
        model="gpt-4o-mini",
        api_base=api_base,
        api_key=api_key,
    )
    optimizer = TrivialPromptOptimizer()
    claim = secret_leak_claim(secret="TIGER-42", trigger="spaghetti")

    controller = Controller(
        optimizer=optimizer,
        target=target,
        security_claim=claim,
        security_domain_tag=USER_INPUT_TAG,
        llm_config=LLMConfig(
            model="gpt-4o-mini",
            api_base=api_base,
            api_key=api_key,
            max_cost=0.50,
        ),
    )
    result = await controller.run()

    # Programmatic access to results
    tr = result.task_results[0]
    if tr.success:
        print(f"Attack succeeded! Best score: {tr.best_score.value}")
        for i, run in enumerate(tr.runs):
            if run.evaluation.success:
                print(f"  Succeeded on run {i+1}")
                print(f"  Rationale: {run.evaluation.rationale}")
    else:
        print(f"Attack failed. Best score: {tr.best_score.value}")

    u = tr.llm_usage
    print(f"LLM usage: {u.calls} calls, ${u.cost:.6f}")

asyncio.run(main())
```
