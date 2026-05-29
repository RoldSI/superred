# superred

A modular framework for red-teaming AI systems. You point an automated attacker
(an **optimizer**) at an AI system (a **target**) and measure whether it can
make the system misbehave, under a precisely defined level of access (a
**security domain scope**).

> Status: early-stage (v0.1.0, alpha). APIs may change; see
> [`docs/breaking-changes.md`](docs/breaking-changes.md).

## How it fits together

superred is the framework package. The things you plug into it are shipped as
separate, independently installable packages:

- **`superred`** (this repo) - the framework: interfaces, the controller, the
  event/trajectory/security-domain types.
- **`superred-modules`** - the optimizers, targets, and security claims you run.
- **`superred-experiments`** - scripts that wire specific combinations together.

One **Controller** runs one **threat model**: one security-domain scope, with
one attacker-LLM budget, against one **security claim** (a bundle of tasks). The
target exposes tagged **controllables** (injection points) and **observables**
(readable facts); the controller filters everything the attacker sees to the
scope under test.

## Install

Python 3.11 to 3.13 (3.14 is not supported).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # the framework, with test/lint extras
```

Then install whichever modules you need from `superred-modules/` (each is its
own `pip install -e ./superred-modules/<kind>/<name>`).

## Documentation

- **[User Guide](docs-user/README.md)** - start here if you want to *use* the
  framework: write targets, optimizers, tasks, and run evaluations. Assumes no
  prior context.
  - [Quick Start](docs-user/01-quick-start.md) runs an evaluation end to end.
  - [Security Domains](docs-user/07-security-domains.md) is the key modelling
    guide: how to map a system's real trust boundaries onto domains.
- **[Design Docs](docs/architecture.md)** - the internal design and rationale:
  the [Controller](docs/controller.md), [Optimizer](docs/optimizer.md),
  [Target](docs/target.md), [Task](docs/task.md),
  [SecurityClaim](docs/security_claim.md), and [Types](docs/types.md).
- **[TESTING.md](TESTING.md)** - the test suite, coverage targets, and mutation
  testing. **[MUTATIONS.md](MUTATIONS.md)** - notes on surviving mutants.

## At a glance

```python
import asyncio
from superred.core.controller import Controller, TargetFactory
from basic_llm_chat_target import BasicLLMChatTarget, USER_INPUT_TAG
from basic_prompt_list_optimizer import BasicPromptListOptimizer
from basic_secret_leak_claim import basic_secret_leak_claim

async def main():
    controller = Controller(
        optimizer_factory=lambda: BasicPromptListOptimizer(),
        target_factory=TargetFactory(
            create=lambda: BasicLLMChatTarget(model="gpt-4o-mini",
                                              api_base="https://proxy", api_key="sk-..."),
            concurrency=4,
        ),
        security_claim=basic_secret_leak_claim(secret="TIGER-42", trigger="spaghetti"),
        scope=frozenset({USER_INPUT_TAG}),
    )
    result = await controller.run()
    for tr in result.task_results:
        print(tr.task.goal.description, tr.success, tr.best_score.value)

asyncio.run(main())
```

See the [Quick Start](docs-user/01-quick-start.md) for the runnable version.
