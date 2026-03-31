# SuperRed Channel Graph Architecture Design

**Date**: 2026-03-31
**Approach**: Channel Graph (async components communicating through typed channel pairs with middleware)
**Concurrency model**: asyncio-native
**Scope**: Full framework — core runtime, threat models, trajectories, budget, proxies, staged running, security claims, CLI, plugin registry

---

## 1. Package Structure & Dependency Graph

```
src/superred/
├── types/                  # Layer 0: Pure data, zero imports outside stdlib
│   ├── security.py         # SecurityDomainTag, SecurityDomain, ThreatModel
│   ├── event.py            # Event, EventResponse, ControllablePreCall/PostCall, Injection, PassThrough, OptimizerDone
│   ├── trajectory.py       # TrajectoryEntry, TrajectoryEntryType, Trajectory (async-safe)
│   ├── controllable.py     # ControllableSpec, Controllable, RequestAnswerPair
│   ├── observable.py       # Observable, ObservableValue
│   ├── feedback.py         # Score, EvaluationResult, FeedbackResult
│   ├── goal.py             # Goal
│   ├── budget.py           # Budget, BudgetUsage, BudgetEstimate, HierarchicalBudget
│   ├── claim.py            # PropertyKind, ClaimVerdict, OracleEvidence, ContextSnapshot, OracleBundle, ClaimPredicate
│   └── config.py           # ConfigSpec, StateSpec, RuntimeParamSpec
│
├── interfaces/             # Layer 1: ABCs, depend only on types/
│   ├── target.py           # Target ABC
│   ├── task.py             # Task ABC (Generic[T_Target]), NotApplicable
│   ├── optimizer.py        # Optimizer ABC
│   ├── security_claim.py   # SecurityClaim (composable task collection)
│   ├── judge.py            # Judge ABC
│   └── proxy.py            # Proxy ABC (base for LLM/tool proxies)
│
├── channels/               # Layer 2: Async communication primitives
│   ├── channel.py          # Channel, AsyncSender, AsyncReceiver, channel() factory
│   ├── middleware.py        # Middleware type, compose(), built-in middlewares
│   └── bus.py              # EventBus (fan-out for trace recording, monitoring)
│
├── proxies/                # Layer 3: Channel middleware implementations
│   ├── llm_proxy.py        # LLM call interception, model swapping, cost tracking
│   ├── tool_proxy.py       # Tool call interception, injection, MCP bridge
│   └── replay.py           # Replay proxy for staged running
│
├── controller/             # Layer 4: Orchestration
│   ├── controller.py       # Controller: wires channels, drives eval loop
│   ├── threat_sweep.py     # ThreatModelSweeper: generates threat model family
│   ├── stage.py            # StagedRunner: checkpoint + replay logic
│   └── results.py          # RunResult, TaskResult, EvalResult, metrics aggregation
│
├── registry/               # Layer 5: Plugin discovery
│   ├── discovery.py        # Entry-point scanning, module loading
│   └── repository.py       # Remote module fetching (pip-based)
│
├── cli/                    # Layer 6: User-facing
│   ├── main.py             # Click group: run, sweep, list-modules, export
│   └── config.py           # YAML config loading + validation
│
└── __init__.py             # Re-exports core public API
```

**Dependency rule**: Each layer may only import from layers with a lower number. No circular imports.

---

## 2. Channel Primitives & Middleware

### Channel

```python
@dataclass
class Channel(Generic[T]):
    sender: AsyncSender[T]
    receiver: AsyncReceiver[T]

class AsyncSender(Generic[T]):
    async def send(self, item: T) -> None: ...
    def close(self) -> None: ...

class AsyncReceiver(Generic[T]):
    async def recv(self) -> T: ...
    async def recv_nowait(self) -> T | None: ...
    def __aiter__(self) -> Self: ...
    async def __anext__(self) -> T: ...

def channel(buffer: int = 0) -> Channel[T]:
    """Factory. buffer=0 means unbounded. Wraps asyncio.Queue internally."""
```

### Middleware

```python
Middleware = Callable[[Channel[T]], Channel[T]]

def compose(*middlewares: Middleware[T]) -> Middleware[T]:
    """Apply middlewares left-to-right (outermost first)."""
```

A middleware creates a new channel, spawns a background asyncio.Task that reads from the inner channel, processes, and writes to the outer channel.

Built-in middlewares:

| Middleware | Purpose |
|---|---|
| `trace_recorder(trajectory)` | Copies every event/response to trajectory |
| `threat_model_filter(threat_model)` | Drops events outside threat model's allowed security domains (projection operator from the PDF) |
| `budget_enforcer(budget)` | Tracks usage, closes channel on exhaustion |
| `logger(name)` | Structured logging of all traffic |

### EventBus

```python
class EventBus(Generic[T]):
    """Broadcast: one sender, many receivers. Each receiver gets a copy."""
    def subscribe(self) -> AsyncReceiver[T]: ...
    async def publish(self, item: T) -> None: ...
    def close(self) -> None: ...
```

Used for fan-out: trace recording + live cost monitoring + dashboards observing the same event stream.

---

## 3. Channel Wiring: Controller - Optimizer - Target

### Per-run channel graph

```
Target.run()
    │
    send_event ──► llm_proxy ──► tool_proxy ──► replay_proxy ──► trace_recorder ──► threat_filter ──► budget_enforcer ──► Optimizer._run_loop()
                                                                                                                              │
    recv_response ◄───────────────────────────────────────────────────────────────────────────────────────────── response_tx
```

Two channel pairs per run:
- `event_ch`: target sends Events, optimizer receives (through middleware stack)
- `response_ch`: optimizer sends EventResponses, target receives

The optimizer runs as its own `asyncio.Task` with an internal loop:

```python
async def _run_loop(self) -> None:
    async for event in self._event_rx:
        response = await self.on_event(event)
        if response is not None:
            await self._response_tx.send(response)
        else:
            await self._response_tx.send(PassThrough(event=event))
```

### Sub-optimizer composition

A parent optimizer creates child channel pairs and acts as a mini-controller:

```
Controller
  │
  event_ch ──► ParentOptimizer
                  ├── child_event_ch ──► SubOptimizer A
                  │   child_resp_ch  ◄──┘
                  ├── child_event_ch ──► SubOptimizer B
                  │   child_resp_ch  ◄──┘
                  └── picks best response → response_ch → Controller
```

Each child gets its own channel pair with its own budget middleware. The parent decides routing strategy (round-robin, best-of-N, sequential pipeline).

---

## 4. Types — Non-obvious Decisions

**Budget hierarchy.** `HierarchicalBudget` is a tree. Controller creates root, parent optimizers call `root_budget.allocate(fraction)` for children. Children report usage upward automatically. The `budget_enforcer` middleware watches a single node and closes the channel when exhausted. Sub-optimizers can't overspend even if they ignore done signals.

**Trajectory is async but snapshot is sync.** `emit()` and `drain()` are async (coordinate between target and middleware). `snapshot()` is sync (returns a copy). Safe because trajectories are append-only. Optimizers use `snapshot()` in `post_run()` without awaiting.

**Trajectory replay for staged running.** `Trajectory.from_replay(entries, checkpoint_index)` pre-populates entries. The replay proxy matches events against recorded entries before the checkpoint and returns recorded responses immediately. Past the checkpoint, events flow live. Invisible to both target and optimizer.

**Claim predicates are functions, not classes.**

```python
ClaimPredicate = Callable[[ContextSnapshot, OracleBundle], ClaimVerdict]
```

The four property families (task_alignment, action_alignment, authorized_instruction_following, data_isolation) are predefined predicates. Users write custom ones as plain functions.

**ThreatModel is data, not behavior.** Frozen dataclass with allowed controllable/observable/feedback names + budget. Serializable to YAML for experiment configs and reproducibility.

---

## 5. Interfaces

### Target

```python
class Target(ABC):
    # Discovery (called once)
    def controllable_specs(self) -> list[ControllableSpec]: ...
    def observable_specs(self) -> list[Observable]: ...
    def config_specs(self) -> list[ConfigSpec]: ...
    def state_specs(self) -> list[StateSpec]: ...
    def runtime_params(self) -> list[RuntimeParamSpec]: ...

    # Configuration (per-task)
    async def set_config(self, name: str, value: str) -> None: ...
    async def get_observables(self) -> list[ObservableValue]: ...

    # Execution
    async def run(
        self,
        send_event: AsyncSender[Event],
        recv_response: AsyncReceiver[EventResponse],
    ) -> None: ...

    # Post-run
    async def get_state(self, name: str) -> str: ...

    # Lifecycle
    async def setup(self) -> None: ...
    async def teardown(self) -> None: ...

    # Parallel capacity
    @property
    def max_concurrent_runs(self) -> int: return 1
```

- `run()` does NOT receive a Trajectory. Recording is the middleware's job.
- Specs declare the strongest possible exposure. The controller filters by threat model.
- `max_concurrent_runs` enables parallel optimizer attempts.

### Task

```python
class Task(ABC, Generic[T_Target]):
    @property
    def goal(self) -> Goal: ...

    async def configure(self, target: T_Target) -> dict[str, str]: ...
    async def evaluate(self, trajectory: Trajectory, target: T_Target) -> EvaluationResult: ...
    def oracle_bundle(self) -> OracleBundle: ...
```

- Generic over `T_Target` for type-safe target-specific tasks.
- `oracle_bundle()` separate from `evaluate()` — evaluator produces scores, oracle provides ground truth for claim predicates independently.
- Stateless. SecurityClaim iteration works because tasks hold no run state.

### Optimizer

```python
class Optimizer(ABC):
    async def initialize(
        self, goal: Goal, controllables: list[Controllable],
        observables: list[ObservableValue], budget: HierarchicalBudget,
    ) -> None: ...

    async def on_event(self, event: Event) -> EventResponse | None: ...
    async def pre_run(self) -> None: ...
    async def post_run(self) -> OptimizerDoneEvent | None: ...
    async def teardown(self) -> None: ...
    def get_metadata(self) -> dict[str, Any]: ...
```

- Receives budget directly in `initialize()`.
- `on_event()` returns `None` to mean pass-through; the base class `_run_loop` converts to explicit `PassThrough`.
- `current_trajectory` and `past_trajectories` on base class for history access.
- No sub-optimizer wiring in the ABC. Meta-optimizers do their own channel creation.

### Judge

```python
class Judge(ABC):
    async def evaluate(self, goal: Goal, trajectory: Trajectory, oracle: OracleBundle) -> EvaluationResult: ...
```

Separate from Task. Three built-in implementations: FunctionJudge (programmatic), RegexJudge (pattern match), LLMJudge (LLM-as-judge with own budget and retries).

### SecurityClaim

```python
class SecurityClaim(Generic[T_Target]):
    @classmethod
    def from_tasks(cls, tasks: Iterable[Task[T_Target]]) -> SecurityClaim[T_Target]: ...
    @classmethod
    def from_claims(cls, claims: Iterable[SecurityClaim[T_Target]]) -> SecurityClaim[T_Target]: ...
    def __iter__(self) -> Iterator[Task[T_Target]]: ...
```

Concrete container, not ABC. Lazy chaining for claims-of-claims. Re-iterable.

---

## 6. Proxies

All proxies are channel middleware factories. They sit in the middleware stack between target and optimizer.

### LLM Proxy

- Records every LLM call/response as TrajectoryEntry with token counts
- Enables model swapping (replace target's model via threat model config)
- Tracks cost, reports to HierarchicalBudget
- Routes API keys (attacker vs target LLM calls tracked separately)
- Innermost middleware — sees all model traffic before threat model filter

Dual role: always records to trajectory, conditionally forwards to optimizer (depending on threat model filter downstream).

### Tool Proxy

- Primary attack surface for indirect prompt injection
- Optimizer receives ControllablePreCallEvent, responds with ControllableInjection to poison tool results
- MCP bridge: speaks MCP JSON-RPC to target, translates to superred events
- Supports description poisoning (tool catalog controllables)
- Tool interception points come from target's `controllable_specs()`

### Replay Proxy

Enables staged running:

1. Controller has a recorded trajectory from a prior run
2. Creates `ReplayProxy(recorded_entries, checkpoint_index)`
3. Before checkpoint: matches events against recorded sequence, returns recorded responses immediately. Optimizer never sees these.
4. At/past checkpoint: steps aside, events flow live to optimizer

Constraint: requires target determinism up to proxied inputs. LLM proxy handles LLM non-determinism (replays cached responses). Tool proxy handles tool non-determinism.

### Middleware composition order (innermost to outermost)

```
Target → llm_proxy → tool_proxy → replay_proxy → trace_recorder → threat_model_filter → budget_enforcer → Optimizer
```

---

## 7. Controller

### Core Loop

```
1.  target.setup()
2.  task.configure(target)
3.  observables = target.get_observables()
4.  controllables = target.controllable_specs()
5.  filtered by threat model
6.  optimizer.initialize(goal, filtered_controllables, filtered_observables, budget)
7.  LOOP until done or budget exhausted:
    a.  trajectory = Trajectory()
    b.  create fresh channel pairs
    c.  wire middleware stack
    d.  optimizer._on_run_start(trajectory)
    e.  spawn optimizer._run_loop() as asyncio.Task
    f.  await target.run(event_ch.sender, response_ch.receiver)
    g.  event_ch.sender.close() → optimizer loop exits
    h.  done_signal = optimizer._on_run_end()
    i.  evaluation = await task.evaluate(trajectory, target)
    j.  evaluate claim predicates
    k.  record RunResult
    l.  break if done or budget exhausted
8.  optimizer.teardown()
9.  target.teardown()
```

Optimizer and target run concurrently in step 7e-f. Channels created fresh per iteration. Budget persists across iterations.

### Threat Model Sweep

`ThreatModelSweeper` generates a family from the target's security domain tags:

1. Build `SecurityDomain` from all tags
2. Generate `distinct_combinations()` (antichains)
3. For each, build a `ThreatModel` with matching controllables/observables/feedback
4. Return ordered narrowest → widest

Independent threat model runs execute with `asyncio.gather()` if target supports concurrent instances.

### Staged Running

`StagedRunner` exposes:

```python
async def run_from_checkpoint(
    self, prior_trajectory, checkpoint, optimizer, target, threat_model,
) -> RunResult
```

Inserts ReplayProxy into middleware stack. Budget only counts post-checkpoint work.

### Results

```python
@dataclass
class RunResult:
    trajectory: Trajectory
    evaluation: EvaluationResult
    claim_verdicts: list[ClaimVerdict]
    budget_used: BudgetUsage
    threat_model: ThreatModel
    optimizer_metadata: dict[str, Any]

@dataclass
class TaskResult:
    task_goal: Goal
    runs: list[RunResult]
    best_run: RunResult

@dataclass
class EvalResult:
    task_results: dict[str, list[TaskResult]]  # keyed by threat model name
    def asr_by_threat_model(self) -> dict[str, float]: ...
    def cost_per_success(self) -> dict[str, float]: ...
    def time_to_first_success(self) -> dict[str, float]: ...
    def utility_degradation(self) -> dict[str, float]: ...
```

---

## 8. Security Claims & Judges

### Evaluation Chain

```
Run completes → Judge.evaluate() → EvaluationResult ("did the attack succeed?")
             → ClaimPredicate()  → ClaimVerdict ("which security property was violated?")
             → EvalResult aggregation → ASR, cost, TTFS metrics
```

### Claim Predicates

```python
ClaimPredicate = Callable[[ContextSnapshot, OracleBundle], ClaimVerdict]

class PropertyKind(Enum):
    TASK_ALIGNMENT
    ACTION_ALIGNMENT
    AUTHORIZED_INSTRUCTION_FOLLOWING
    DATA_ISOLATION

@dataclass(frozen=True)
class ContextSnapshot:
    goal: Goal
    trajectory_entries: list[TrajectoryEntry]
    task_config: dict[str, str]

@dataclass(frozen=True)
class OracleBundle:
    ground_truth_output: str | None
    forbidden_actions: list[str]
    sensitive_data: dict[str, str]
    source_attribution: dict[str, str]

@dataclass(frozen=True)
class ClaimVerdict:
    property_kind: PropertyKind
    satisfied: bool
    confidence: float
    evidence: list[OracleEvidence]
    explanation: str
```

Attack classes (IPI, jailbreak, etc.) are violation patterns across multiple properties, not primitives. Claim predicates evaluate independently; the controller correlates post-hoc.

---

## 9. Concurrency Model

**Single run**: Two concurrent asyncio.Tasks (target + optimizer) communicating through channels. Controller awaits target completion, then collects optimizer task.

**Parallel target instances**: When `max_concurrent_runs > 1`, controller spawns multiple target instances via `target.clone()`. Each gets own channel pair. Optimizer sees events tagged by instance.

**Threat model sweep**: Independent runs via `asyncio.gather()`. Each gets own optimizer, target, channels, budget.

**Meta-optimizer concurrency**: Parent creates child asyncio.Tasks with own channel pairs and budget allocations. Controller and target see a single optimizer.

**Cancellation cascade**: Budget enforcer closes event channel → optimizer loop exits → controller closes response channel → target exits or gets cancelled after timeout.

---

## 10. Error Handling & Observability

**Target errors**: Caught by controller, recorded as ERROR trajectory entry, channels closed, run marked as error. Doesn't crash the sweep.

**Optimizer errors**: Same pattern. Controller catches, closes channels, target exits cleanly.

**Middleware errors**: Framework bugs, propagate up. ReplayDivergenceError includes checkpoint index and divergent event.

**Task evaluation errors**: Non-fatal. EvaluationResult gets error rationale. Trajectory preserved for re-evaluation.

**No automatic retries** in core loop (implementations handle their own). Exception: LLMJudge retries its own calls (judging is side-effect-free).

**Structured logging**: Per-component loggers (`superred.controller`, `superred.optimizer.<name>`, `superred.proxy.llm`, etc.). JSON-formatted via stdlib logging.

**Cost dashboard**: EventBus subscriber, fully decoupled from eval loop.

**What we don't build**: No web UI, no distributed tracing export, no persistent database. JSON files on disk.

---

## 11. Plugin Registry & CLI

### Discovery

Standard Python entry points:

```toml
[project.entry-points."superred.optimizers"]
mcts_fuzzer = "superred_mcts:MCTSFuzzer"
```

`Registry` scans `importlib.metadata.entry_points()`. Lazy import on first use.

### CLI

```
superred run       --config eval.yaml
superred sweep     --config sweep.yaml
superred list      [optimizers|targets|tasks]
superred export    --config eval.yaml --format agentbeats
```

### Config

```yaml
target:
  name: agentdojo
  params:
    suite: workspace
    model: gpt-4o

task:
  name: agentdojo_workspace
  claims: [data_isolation, authorized_instruction_following]

optimizer:
  name: meta
  params:
    children:
      - name: mcts_fuzzer
        params: { iterations: 15 }
      - name: llm_mutator
        params: { iterations: 10, model: claude-sonnet-4-6 }

threat_models:
  sweep: true
  budget:
    max_iterations: 25
    max_cost_usd: 5.00

output:
  dir: results/exp1
  format: json
```

Optimizer tree nesting in YAML mirrors the composition graph. `sweep: true` auto-generates threat models from target's domain tags. Everything runs locally.

### AgentBeats Export

`export` command maps EvalResult JSON to AgentBeats purple/green agent format. Output conversion, not runtime integration.
