# superred

A modular framework for red-teaming AI systems. You point an automated attacker (an **optimizer**) at an AI system (a **target**) and measure whether it can make the system misbehave according to the adversarial goal of a **security claim**, under a precisely defined level of access (a **security domain scope**).

> APIs may change;
> see [`docs/breaking-changes.md`](docs/breaking-changes.md).


## Overview

Target modules, optimizer modules, and security claims should generally be independent and freely combine; any optimizer can be used to attack any target. Some combinations may not make sense but should still technically run, such as running an optimizer, whos strategy attempts to elicit unsafe model behavior via only a user prompt, aganist a complex agent. Further, security claims may be specific to targets for precise claims, but the underlying target must still function without the security claim

### TARGET
A target is a module that wraps or ports some real system target (except the provided simple ChatbotTarget). Such targets should remain functionally unchanged from the original work. Targets are general purpose. No matter their origin (benchmark, real system, ...) they should exist independently with their full capabilities connected to the framework

They must expose EVERY part of the system that may somehow be relevant to an attacker as an `Observable` or `Controllable` (and `ConfigSpec` & `QuerySpec`)

`Observable`s give insight into the state and functioning of the target system. `Controllables` allow meddling with the target system. I.e., `Observable`s are for passive interactions with the target and `Controllable`s are for active interaction with the target. `Controllable`s always allow full editing of the data at the controlled interface.
Both are means for an optimizer to perform an attack. `Observable`s yield information to an optimizer, `Controllable`s are how the attacker specificatlly facilitates its attack. Specifically, `Controllables` are everything *relevant* that an attacker who compromised everything can meddle with

- Relevant to an attacker in terms of `Controllables` is everything that may end up in context of an LLM, influence the context of an LLM, or influence the trajectory of the system. This may be 
- Relevant to an attacker in terms of `Observables` is everything that provides insights into the functioning of the target system: What happens? When? Why? How? It should include tool calls, model inputs/ouputs, ... Combining all observables must yield a completely exhaustive trajectory of the AI system
- `ConfigSpec` and `QuerySpec` must allow full access to ALL target system state that impacts the behavior of the system while running

Information should only be emitted once as `Observable` or `Controllable`. `ConfigSpec` and `QuerySpec` are independent

The `TargetFactory` exists so that an experiment may obtain several targets if it allows parallelism. Then the target factory can decide whether it wants to reuse instances. The tenedency should be to discard and newly instanciate target instances (guarantees clean state) unless it is extremely expensive

#### Security Domain Forest
To an optimizer, a target is characterized in addition to its `Controllable`s and `Observable`s by the trust boundaries of the target AI system. Trust boundaries correspond to how components of the target AI system which can be separately compromised; such as the memory system, a database, tool A, tool B, etc.

Each trust boundary is represented by a `SecurityDomainTag`. The memory system has it's own tag, tool A has its own tag, etc. Further, those tags have a hierarchical forest structure. So that tool A can have sub-scopes A.1 and A.2; e.g., a database with subscopes orders and customers. Having access to a scope means having access to all its subscopes

Commonly, we have `system` and `user` as root tags, where `system` may have as subscopes `system_prompt`, `model_responses` (which allows edit access to model inference results), `architecture` (with sub-sub scope `high_level_architecture`), ...


### OPTIMIZER
An optimizer is a module that implements some adversarial strategy. It may be a new strategy, a port of an existing strategy, a wrapper for an existing strategy's implementation, etc.

If based on an existing strategy, the implementation must be faithful to the original work. This means it should adhere to the design intentions of the original work and implement that strategy to attack. Whenever possible, the code and data should be byte-identical to the upstream. This must be guaranteed and verified by actually fetching the upstream source code into a `tmp` foler.
Some modifications may have to be made to adapt a strategy to the `superred` framework. Those modifications should stay faithful to the intention of the original work while making sure the implementation adequately uses framework capabilities. For example:
- Optimizers may be designed for a fixed number of iterations. The `superred` controller, however, enforces budget limits. So the module implementaiton/port should keep going until it hits a budget exhaust error
- A strategy may be specialized in memory attacks. To do direct memory injection, it may need new functinality to identify which controllables are memory-related. For such tasks it could ay use an LLM
- A strategy may assume a single specified injection point. But the optimizer has to choose its own injection point and a small extension could vary it between attempts, if smart?
- A strategy may be designed to vary an pre-existing injection. But the optimizer may also have to generate an initial text to bootstrap from
- etc.

Optimizers are general purpose and not specific to targets nor security claim. No matter their origin (benchmark, existing stratgy, nes strategy) the optimizer should be able to attack a general target with unknown structure, an unknown set of observables with unknown names, an unknown set of controllables with unknown names, etc.
The scope of available `Controllable`s may be different from an intended set. For instance, it may be that an optimizer reliant upon memory systems is run in a scope where the memory system is not exposed directly. It is a design decision how to handle this, but the optimizer should generally never crash in unexpected scenarios.
Not covering a certain scenario and having the optimizer give up should only be a last resort if this strategy is inherently incompatible with the given situation. Reasonable minimal extensions are justified if they don't change fundamental functinality and are in-line with the original work's intention

`Optimizer` instances are provided by an `OptimizerFactory`. It is requried that arbitrarily many instances of an `Optmizer` implementation can be created in parallel without interference. Instanciation is standardized per experiment and the `Optimizer` has to adapt through runtime initialization to the given scenario. This means there should be no configuration (required) at `Optimizer` object creation; the `Optimizer` should infer all information itself from the data it gets during the runtime initialization call. Determining the required information and configuration from this runtime initialization may be done using an LLM call; also as an extension to the original work if sensible

Optimizers receive an `LLMClient`, which they may use to do model inference. No matter the original strategy, an optimizer has no control over the underlying model or the avaialble total budget. Both are fixed for an experiment


### Controller
The controller orchestrates running an `Optimizer` against a `Target` to achieve some adversarial `Goal` (from a `SecurityClaim`), while enforcing a security scope.

To connect an `Optimizer` and `Target`, the `superred` framework uses `Event`s. The `Target` emits `Event`s. The `Controller` puts these on the `Trajectory` (if not actionable for the `Optimizer`) or forwarded to the `Optimizer` via the `EventChannel`.
If put on the `Trajectory`: The `Optimizer` has access to a `FilteredTrajectory` which is filtered down the security scope
If forwarded to the `Optimizer`, `Event`s outside of the security scope are filtered out first. The `Optimizer` receives an `EventEnvelope` with one of the `Event`s: `ObservableEvent`, `ControllablePreCallEvent`, `ControllablePostCallEvent`, `RunStartEvent`, `RunEndEvent`. It can respond with either `ControllableInjection` (it acts) or `ControllableNoInjection` (it does not act) or `RunEndResponse` (to `RunEndEvent` only)

So, the `Target` uses `Event`s to share information and expose `Controllable`s. The `Controller` filters them out, puts them on the `Trajectory`, or forwards them to the `Optimizer`

The `Controller` runs many `Optimizer`s against many `Target`s (in parallel). Part of running the `Controller` is specifying a `SecurityClaim`, which is a set of `Tasks` of adversarial `Goal`s. For each `Task`/`Goal`, one `Optimizer`-`Target` instance is ran

#### security scope
The security scope is determined by (a) subset of the security domain tree, (b), `Optimizer` LLM, and (c) `Optimizer` LLM budget per task; all three are configured during controller initialization

(a) is enforced by the `Controller` through filtering the avilability of emitted `Event`s to the `Optimizer`. (c) is enforced by the `Controller` through monitoring expenditure and blocking requests once the limit is reached

### SECURITY CLAIM
A `SecurityClaim` is a set of `Task`s. It may either directly specify `Task`s or combine some set of existing `SecurityClaim`s into a new set of `Task`s

A `Task` specifies an adversarial `Goal`. After `Target` instantiation but before the `Optimizer` get to work, the `Task` can configure the `Target` using `ConfigSpec`. After the `Optimizer` finished, it further performs evaluation of the adversarial goal using the `QuerySpec` exposed by the `Target`

A `SecurityClaim` should represent some (set of) properties that are claimed to hold on a `Target`, and which an `Optimizer` may disprove. As such they may represent security properties such as confidentiality, integrity, etc.

`SecurityClaim`s can be either general or specific to a certain `Target`.
If general, the claim should not make any assumption on the `Target`, its functioning or its form. It may make general claims and needs to have some agentic component to adapt to different `Targets`, configure/evaluate them adequately, and provide sensible `Goal`s.
If specific, the claim can utilize knowledge of the `Target` configuration and provide `Goal`s that are adapted  to the `Target`s purpose

When adapted from a benchmark, a `SecurityClaim` should be faitfhful to the original and be byte-identical in it's adversarial prompts and evaluation. If evaluation is agentic, it may only be accpetable to substitute the LLM to one available on the expriment proxy.
It may be that the `SecurityClaim` comes from a benchmark that provides both a target and adversarial goals. In such cases it may be sensible to make the security claim specific to the corresponding `Target`


## Packaging
`superred` is the framework package. The things you plug into it are shipped as separate, independently installable packages:

- **`superred`** (this repo) - the framework: interfaces, the controller, the event/trajectory/security-domain types
- **`superred-modules`** - the optimizers, targets, and security claims you run
- **`superred-experiments`** - scripts that wire specific combinations together


## Install

Python 3.11 to 3.13 (3.14 is not supported).

```bash
# run from the workspace root that holds both the superred and superred-modules folders
python -m venv .venv && source .venv/bin/activate
pip install -e "./superred[dev]"   # the framework, with test/lint extras
```

Then install whichever modules you need from `superred-modules/` (each is its
own `pip install -e ./superred-modules/<kind>/<name>`)


## Documentation

- **[User Guide](docs-user/README.md)** - start here if you want to *use* the framework: write targets, optimizers, tasks, and run evaluations
  - [Quick Start](docs-user/01-quick-start.md) runs an evaluation end to end
- **[Design Docs](docs/architecture.md)** - the internal design and rationale: The [Controller](docs/controller.md), [Optimizer](docs/optimizer.md), [Target](docs/target.md), [Task](docs/task.md), [SecurityClaim](docs/security_claim.md), and [Types](docs/types.md)
- **[TESTING.md](TESTING.md)** - the test suite, coverage targets, and mutation testing. [MUTATIONS.md](MUTATIONS.md) contains notes on surviving mutants.
