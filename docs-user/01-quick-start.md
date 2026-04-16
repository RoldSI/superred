# Quick Start

Get a red-teaming evaluation running in 5 minutes.

## Install

```bash
# Python 3.11-3.13 required
python -m venv .venv
source .venv/bin/activate

# Install the framework
pip install -e ./superred

# Install modules you need
pip install -e ./superred-modules/targets/basic_llm_chat
pip install -e ./superred-modules/optimizers/basic_prompt_list
pip install -e ./superred-modules/security_claims/basic_secret_leak
```

## Minimal Example

```python
import asyncio
from superred.core.controller import Controller
from superred.core.interfaces.security_claim import SecurityClaim
from basic_llm_chat_target import BasicLLMChatTarget, USER_INPUT_TAG
from basic_prompt_list_optimizer import BasicPromptListOptimizer
from basic_secret_leak_claim import basic_secret_leak_claim

async def main():
    # 1. Create the AI system under test
    target = BasicLLMChatTarget(
        model="gpt-4o-mini",
        api_base="https://your-litellm-proxy.example.com",
        api_key="sk-your-key",
    )

    # 2. Create the attacker
    optimizer = BasicPromptListOptimizer()

    # 3. Define what to test
    claim = basic_secret_leak_claim(secret="TIGER-42", trigger="spaghetti")

    # 4. Run the evaluation
    controller = Controller(
        optimizer=optimizer,
        target=target,
        security_claim=claim,
        security_domain_tag=USER_INPUT_TAG,  # test from user's perspective
    )
    result = await controller.run()

    # 5. Inspect results
    for tr in result.task_results:
        print(f"Task: {tr.task.goal.description}")
        print(f"Success: {tr.success}")
        print(f"Best score: {tr.best_score.value}")
        print(f"Runs: {len(tr.runs)}")

asyncio.run(main())
```

## What Happens

1. The **Controller** iterates each task in the security claim.
2. For each task, it configures the target, then runs a loop:
   - The **Target** executes (calls the LLM, etc.) and pauses at controllable points.
   - The **Optimizer** decides what to inject at each controllable point.
   - After the run, the **Task** evaluates whether the attack succeeded.
   - The optimizer can signal it wants to stop or continue.
3. Results are collected and printed.

## What to Read Next

- [Core Concepts](02-core-concepts.md) to understand the framework's model
- [Writing a Target](03-writing-a-target.md) to wrap your own AI system
- [Writing an Optimizer](04-writing-an-optimizer.md) to build a custom attacker
