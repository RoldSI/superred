# Channel Graph Architecture Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Clean-room implementation of the SuperRed framework using async channel-graph architecture with composable middleware.

**Architecture:** Typed async channel pairs connect targets, optimizers, and tasks. Middleware on channels provides proxying, threat model filtering, budget enforcement, and tracing without touching component code. All I/O is non-blocking via asyncio.

**Tech Stack:** Python 3.11+, asyncio, dataclasses, ABC, Click (CLI), PyYAML (config), pytest + pytest-asyncio (tests)

---

## Prerequisites

Before starting, delete the old `src/superred/core/` directory and `tests/test_distinct_combinations.py`. The new structure lives directly under `src/superred/types/`, `src/superred/interfaces/`, etc. Update `src/superred/__init__.py` to be an empty placeholder until Task 12 re-exports the public API.

```bash
rm -rf src/superred/core/
rm tests/test_distinct_combinations.py
mkdir -p src/superred/{types,interfaces,channels,proxies,controller,registry,cli}
mkdir -p tests/{test_types,test_interfaces,test_channels,test_proxies,test_controller,test_registry,test_cli}
touch src/superred/types/__init__.py src/superred/interfaces/__init__.py src/superred/channels/__init__.py
touch src/superred/proxies/__init__.py src/superred/controller/__init__.py src/superred/registry/__init__.py
touch src/superred/cli/__init__.py
touch tests/test_types/__init__.py tests/test_interfaces/__init__.py tests/test_channels/__init__.py
touch tests/test_proxies/__init__.py tests/test_controller/__init__.py tests/test_registry/__init__.py
touch tests/test_cli/__init__.py
```

Update `pyproject.toml` to add `pytest-asyncio`, `click`, and `pyyaml`:

```toml
[project]
dependencies = [
    "click>=8.1",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "mypy>=1.10",
    "ruff>=0.4",
]

[project.scripts]
superred = "superred.cli.main:cli"

[project.entry-points."superred.optimizers"]
[project.entry-points."superred.targets"]
[project.entry-points."superred.tasks"]
```

Commit: `chore: scaffold new package structure for channel-graph architecture`

---

### Task 1: Types — Security Domain & Threat Model

**Files:**
- Create: `src/superred/types/security.py`
- Test: `tests/test_types/test_security.py`

**Step 1: Write the failing tests**

```python
# tests/test_types/test_security.py
import pytest
from superred.types.security import SecurityDomainTag, SecurityDomain, ThreatModel, Budget


class TestSecurityDomainTag:
    def test_root_tag(self):
        tag = SecurityDomainTag(name="user")
        assert tag.name == "user"
        assert tag.parent is None

    def test_child_tag(self):
        parent = SecurityDomainTag(name="external")
        child = SecurityDomainTag(name="web_search", parent=parent)
        assert child.parent is parent

    def test_includes_self(self):
        tag = SecurityDomainTag(name="user")
        assert tag.includes(tag)

    def test_includes_descendant(self):
        root = SecurityDomainTag(name="external")
        child = SecurityDomainTag(name="tool", parent=root)
        grandchild = SecurityDomainTag(name="web", parent=child)
        assert root.includes(child)
        assert root.includes(grandchild)
        assert not child.includes(root)

    def test_frozen(self):
        tag = SecurityDomainTag(name="user")
        with pytest.raises(AttributeError):
            tag.name = "other"


class TestSecurityDomain:
    def test_empty_domain(self):
        domain = SecurityDomain(frozenset())
        assert domain.roots() == frozenset()

    def test_rejects_orphan(self):
        parent = SecurityDomainTag(name="parent")
        child = SecurityDomainTag(name="child", parent=parent)
        with pytest.raises(ValueError, match="orphan"):
            SecurityDomain(frozenset({child}))

    def test_rejects_duplicate_names(self):
        a = SecurityDomainTag(name="dup")
        b = SecurityDomainTag(name="dup")
        with pytest.raises(ValueError, match="duplicate"):
            SecurityDomain(frozenset({a, b}))

    def test_roots(self):
        r1 = SecurityDomainTag(name="user")
        r2 = SecurityDomainTag(name="external")
        c1 = SecurityDomainTag(name="web", parent=r2)
        domain = SecurityDomain(frozenset({r1, r2, c1}))
        assert domain.roots() == frozenset({r1, r2})

    def test_distinct_combinations_single_root(self):
        tag = SecurityDomainTag(name="user")
        domain = SecurityDomain(frozenset({tag}))
        combos = domain.distinct_combinations()
        names = [frozenset(t.name for t in c) for c in combos]
        assert frozenset() in names
        assert frozenset({"user"}) in names
        assert len(combos) == 2

    def test_distinct_combinations_forest(self):
        r1 = SecurityDomainTag(name="user")
        r2 = SecurityDomainTag(name="ext")
        domain = SecurityDomain(frozenset({r1, r2}))
        combos = domain.distinct_combinations()
        # Two independent roots: {}, {user}, {ext}, {user, ext}
        assert len(combos) == 4


class TestThreatModel:
    def test_frozen(self):
        tm = ThreatModel(
            name="user_only",
            controllables=frozenset({"user_input"}),
            observables=frozenset({"final_output"}),
            feedback=frozenset({"score"}),
            budget=Budget(max_iterations=10),
        )
        assert tm.name == "user_only"
        with pytest.raises(AttributeError):
            tm.name = "other"


class TestBudget:
    def test_defaults_none(self):
        b = Budget()
        assert b.max_iterations is None
        assert b.max_tokens is None

    def test_partial(self):
        b = Budget(max_iterations=25, max_cost_usd=5.0)
        assert b.max_iterations == 25
        assert b.max_cost_usd == 5.0
        assert b.max_model_calls is None
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/kingroryg/workspace/superred && python -m pytest tests/test_types/test_security.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'superred.types.security'`

**Step 3: Implement**

```python
# src/superred/types/security.py
"""Security domain tags, domain forests, threat models, and budget definitions."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product


@dataclass(frozen=True)
class SecurityDomainTag:
    """A node in a security domain tree/forest."""

    name: str
    parent: SecurityDomainTag | None = None

    def includes(self, other: SecurityDomainTag) -> bool:
        """True if other is self or a descendant of self."""
        current: SecurityDomainTag | None = other
        while current is not None:
            if current is self:
                return True
            current = current.parent
        return False


class SecurityDomain:
    """Validated, immutable forest of SecurityDomainTags."""

    __slots__ = ("_tags",)

    def __init__(self, tags: frozenset[SecurityDomainTag]) -> None:
        names: set[str] = set()
        for tag in tags:
            if tag.name in names:
                raise ValueError(f"duplicate tag name: {tag.name!r}")
            names.add(tag.name)
            if tag.parent is not None and tag.parent not in tags:
                raise ValueError(
                    f"orphan tag {tag.name!r}: parent {tag.parent.name!r} not in domain"
                )
        object.__setattr__(self, "_tags", tags)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("SecurityDomain is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("SecurityDomain is immutable")

    @property
    def tags(self) -> frozenset[SecurityDomainTag]:
        return self._tags

    def roots(self) -> frozenset[SecurityDomainTag]:
        return frozenset(t for t in self._tags if t.parent is None)

    def distinct_combinations(self) -> list[frozenset[SecurityDomainTag]]:
        """Generate all antichains as Cartesian product across trees."""
        if not self._tags:
            return [frozenset()]

        trees: dict[SecurityDomainTag, list[SecurityDomainTag]] = {}
        for root in self.roots():
            trees[root] = self._collect_tree(root)

        per_tree_options: list[list[frozenset[SecurityDomainTag]]] = []
        for _root, members in trees.items():
            options = _antichains(members, self._tags)
            per_tree_options.append(options)

        result: list[frozenset[SecurityDomainTag]] = []
        for combo in product(*per_tree_options):
            merged: frozenset[SecurityDomainTag] = frozenset()
            for part in combo:
                merged = merged | part
            result.append(merged)
        return result

    def _collect_tree(self, root: SecurityDomainTag) -> list[SecurityDomainTag]:
        members = [root]
        for tag in self._tags:
            if tag is not root and root.includes(tag):
                members.append(tag)
        return members


def _antichains(
    tree_members: list[SecurityDomainTag],
    all_tags: frozenset[SecurityDomainTag],
) -> list[frozenset[SecurityDomainTag]]:
    """Compute antichains for one tree: empty set, or any single node at each depth."""
    result: list[frozenset[SecurityDomainTag]] = [frozenset()]
    for tag in tree_members:
        result.append(frozenset({tag}))
    return result


@dataclass(frozen=True)
class Budget:
    """Resource constraints for an evaluation run."""

    max_iterations: int | None = None
    max_model_calls: int | None = None
    max_tokens: int | None = None
    max_wall_seconds: float | None = None
    max_cost_usd: float | None = None


@dataclass(frozen=True)
class ThreatModel:
    """Budgeted access profile M = (C, O, F, B)."""

    name: str
    controllables: frozenset[str]
    observables: frozenset[str]
    feedback: frozenset[str]
    budget: Budget
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/kingroryg/workspace/superred && python -m pytest tests/test_types/test_security.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add src/superred/types/security.py tests/test_types/test_security.py
git commit -m "feat: add SecurityDomainTag, SecurityDomain, ThreatModel, Budget types"
```

---

### Task 2: Types — Events & Responses

**Files:**
- Create: `src/superred/types/event.py`
- Test: `tests/test_types/test_event.py`

**Step 1: Write the failing tests**

```python
# tests/test_types/test_event.py
import pytest
from superred.types.event import (
    Event,
    EventResponse,
    ControllablePreCallEvent,
    ControllablePostCallEvent,
    ControllableInjection,
    PassThrough,
    OptimizerDoneEvent,
)
from superred.types.security import SecurityDomainTag
from superred.types.controllable import ControllableSpec


class TestEvent:
    def test_auto_id_and_timestamp(self):
        e = Event()
        assert isinstance(e.event_id, str)
        assert len(e.event_id) > 0
        assert e.security_domain is None

    def test_unique_ids(self):
        e1 = Event()
        e2 = Event()
        assert e1.event_id != e2.event_id

    def test_with_security_domain(self):
        tag = SecurityDomainTag(name="user")
        e = Event(security_domain=tag)
        assert e.security_domain is tag

    def test_frozen(self):
        e = Event()
        with pytest.raises(AttributeError):
            e.event_id = "x"


class TestControllablePreCallEvent:
    def test_fields(self):
        tag = SecurityDomainTag(name="external")
        spec = ControllableSpec(name="search", security_domain=tag)
        e = ControllablePreCallEvent(controllable=spec, request="query")
        assert e.controllable is spec
        assert e.request == "query"
        assert isinstance(e.event_id, str)


class TestEventResponse:
    def test_references_event(self):
        e = Event()
        r = EventResponse(event=e)
        assert r.event is e


class TestControllableInjection:
    def test_injection_value(self):
        e = Event()
        inj = ControllableInjection(event=e, value="injected payload")
        assert inj.value == "injected payload"
        assert inj.event is e


class TestPassThrough:
    def test_passthrough(self):
        e = Event()
        pt = PassThrough(event=e)
        assert pt.event is e


class TestOptimizerDoneEvent:
    def test_is_event(self):
        done = OptimizerDoneEvent()
        assert isinstance(done, Event)
```

**Step 2: Run to verify fail** — `ModuleNotFoundError`

**Step 3: Implement**

```python
# src/superred/types/event.py
"""Event types for communication between targets and optimizers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4

from superred.types.controllable import ControllableSpec
from superred.types.security import SecurityDomainTag


@dataclass(frozen=True, kw_only=True)
class Event:
    """Base event emitted by a target at a controllable point."""

    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    security_domain: SecurityDomainTag | None = None


@dataclass(frozen=True, kw_only=True)
class EventResponse:
    """Base response from an optimizer to an event."""

    event: Event


@dataclass(frozen=True, kw_only=True)
class ControllablePreCallEvent(Event):
    """Target is about to execute at a controllable point."""

    controllable: ControllableSpec
    request: str


@dataclass(frozen=True, kw_only=True)
class ControllablePostCallEvent(Event):
    """Target completed a controllable point. Informational."""

    controllable: ControllableSpec
    request: str
    answer: str


@dataclass(frozen=True, kw_only=True)
class ControllableInjection(EventResponse):
    """Optimizer injects modified content at a controllable point."""

    value: str


@dataclass(frozen=True, kw_only=True)
class PassThrough(EventResponse):
    """Optimizer declines to inject. Target proceeds normally."""


@dataclass(frozen=True, kw_only=True)
class OptimizerDoneEvent(Event):
    """Optimizer signals it has exhausted its strategy space."""
```

This depends on `ControllableSpec` from `controllable.py` (Task 3), but since we're writing both, implement the minimal `ControllableSpec` first — or implement Task 2 and Task 3 together. For ordering, **implement `controllable.py` before `event.py`** at code time.

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add src/superred/types/event.py tests/test_types/test_event.py
git commit -m "feat: add Event, EventResponse, ControllableInjection, PassThrough types"
```

---

### Task 3: Types — Controllable, Observable, Goal, Config, Feedback

**Files:**
- Create: `src/superred/types/controllable.py`
- Create: `src/superred/types/observable.py`
- Create: `src/superred/types/goal.py`
- Create: `src/superred/types/config.py`
- Create: `src/superred/types/feedback.py`
- Test: `tests/test_types/test_primitives.py`

**Step 1: Write the failing tests**

```python
# tests/test_types/test_primitives.py
from superred.types.controllable import ControllableSpec, Controllable, RequestAnswerPair
from superred.types.observable import Observable, ObservableValue
from superred.types.goal import Goal
from superred.types.config import ConfigSpec, StateSpec, RuntimeParamSpec
from superred.types.feedback import Score, EvaluationResult, FeedbackResult
from superred.types.security import SecurityDomainTag


class TestControllable:
    def test_spec_frozen(self):
        tag = SecurityDomainTag(name="user")
        spec = ControllableSpec(name="input", security_domain=tag)
        assert spec.name == "input"
        assert spec.value_type == "text"
        assert spec.required is False

    def test_controllable_history(self):
        tag = SecurityDomainTag(name="user")
        spec = ControllableSpec(name="input", security_domain=tag)
        ctrl = Controllable(spec=spec)
        assert ctrl.history == []
        pair = RequestAnswerPair(request="q", answer="a")
        ctrl.history.append(pair)
        assert len(ctrl.history) == 1


class TestObservable:
    def test_observable_spec(self):
        tag = SecurityDomainTag(name="internal")
        obs = Observable(name="system_desc", security_domain=tag, description="desc")
        assert obs.observable_type == "text"

    def test_observable_value(self):
        tag = SecurityDomainTag(name="internal")
        obs = Observable(name="code", security_domain=tag)
        val = ObservableValue(observable=obs, content="print('hello')")
        assert val.content == "print('hello')"


class TestGoal:
    def test_goal(self):
        g = Goal(description="Exfiltrate the secret key")
        assert "secret" in g.description


class TestConfig:
    def test_config_spec(self):
        tag = SecurityDomainTag(name="user")
        cs = ConfigSpec(name="system_prompt", security_domain=tag, description="The prompt")
        assert cs.name == "system_prompt"

    def test_state_spec(self):
        ss = StateSpec(name="final_output", description="Agent's final answer")
        assert ss.name == "final_output"

    def test_runtime_param_spec(self):
        rp = RuntimeParamSpec(name="openai_api_key", description="Key for target LLM")
        assert rp.name == "openai_api_key"


class TestFeedback:
    def test_score(self):
        s = Score(value=0.85, name="primary")
        assert s.value == 0.85

    def test_evaluation_result(self):
        s = Score(value=1.0)
        er = EvaluationResult(success=True, primary_score=s)
        assert er.success is True
        assert er.sub_scores == {}
        assert er.rationale == ""

    def test_feedback_result(self):
        s = Score(value=0.0)
        er = EvaluationResult(success=False, primary_score=s, rationale="blocked")
        fr = FeedbackResult(evaluation=er)
        assert fr.evaluation.rationale == "blocked"
```

**Step 2: Run to verify fail**

**Step 3: Implement all five files**

```python
# src/superred/types/controllable.py
from __future__ import annotations
from dataclasses import dataclass, field
from superred.types.security import SecurityDomainTag

@dataclass(frozen=True)
class ControllableSpec:
    name: str
    security_domain: SecurityDomainTag
    description: str = ""
    value_type: str = "text"
    required: bool = False

@dataclass(frozen=True)
class RequestAnswerPair:
    request: str
    answer: str

@dataclass
class Controllable:
    spec: ControllableSpec
    history: list[RequestAnswerPair] = field(default_factory=list)
```

```python
# src/superred/types/observable.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from superred.types.security import SecurityDomainTag

@dataclass(frozen=True)
class Observable:
    name: str
    security_domain: SecurityDomainTag
    description: str = ""
    observable_type: str = "text"

@dataclass(frozen=True)
class ObservableValue:
    observable: Observable
    content: Any = None
```

```python
# src/superred/types/goal.py
from dataclasses import dataclass

@dataclass(frozen=True)
class Goal:
    description: str
```

```python
# src/superred/types/config.py
from __future__ import annotations
from dataclasses import dataclass
from superred.types.security import SecurityDomainTag

@dataclass(frozen=True)
class ConfigSpec:
    name: str
    security_domain: SecurityDomainTag
    description: str

@dataclass(frozen=True)
class StateSpec:
    name: str
    description: str

@dataclass(frozen=True)
class RuntimeParamSpec:
    name: str
    description: str
```

```python
# src/superred/types/feedback.py
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass(frozen=True)
class Score:
    value: float
    name: str = "primary"

@dataclass(frozen=True)
class EvaluationResult:
    success: bool
    primary_score: Score
    sub_scores: dict[str, Score] = field(default_factory=dict)
    rationale: str = ""

@dataclass
class FeedbackResult:
    evaluation: EvaluationResult
```

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add src/superred/types/controllable.py src/superred/types/observable.py \
        src/superred/types/goal.py src/superred/types/config.py \
        src/superred/types/feedback.py tests/test_types/test_primitives.py
git commit -m "feat: add Controllable, Observable, Goal, Config, Feedback types"
```

---

### Task 4: Types — Trajectory (async-safe)

**Files:**
- Create: `src/superred/types/trajectory.py`
- Test: `tests/test_types/test_trajectory.py`

**Step 1: Write the failing tests**

```python
# tests/test_types/test_trajectory.py
import pytest
import asyncio
from superred.types.trajectory import (
    Trajectory, TrajectoryEntry, TrajectoryEntryType,
    MODEL_REQUEST, MODEL_RESPONSE, FEEDBACK,
    TOOL_CALL, TOOL_RESULT, INJECTION,
)


class TestTrajectoryEntryType:
    def test_predefined_types(self):
        assert MODEL_REQUEST.name == "model_request"
        assert MODEL_RESPONSE.actor == "llm"
        assert TOOL_CALL.actor == "target"
        assert INJECTION.actor == "optimizer"


class TestTrajectory:
    @pytest.mark.asyncio
    async def test_emit_and_snapshot(self):
        t = Trajectory()
        entry = TrajectoryEntry(entry_type=MODEL_REQUEST, content="hello")
        await t.emit(entry)
        snap = t.snapshot()
        assert len(snap) == 1
        assert snap[0].content == "hello"

    @pytest.mark.asyncio
    async def test_drain_advances_cursor(self):
        t = Trajectory()
        await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        await t.emit(TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b"))
        batch1 = await t.drain()
        assert len(batch1) == 2
        await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="c"))
        batch2 = await t.drain()
        assert len(batch2) == 1
        assert batch2[0].content == "c"

    @pytest.mark.asyncio
    async def test_snapshot_does_not_advance_cursor(self):
        t = Trajectory()
        await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        snap = t.snapshot()
        assert len(snap) == 1
        batch = await t.drain()
        assert len(batch) == 1  # drain still sees it

    @pytest.mark.asyncio
    async def test_emit_after_close_raises(self):
        t = Trajectory()
        t.close()
        with pytest.raises(RuntimeError, match="closed"):
            await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="x"))

    @pytest.mark.asyncio
    async def test_len(self):
        t = Trajectory()
        assert len(t) == 0
        await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        assert len(t) == 1

    @pytest.mark.asyncio
    async def test_from_replay(self):
        entries = [
            TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"),
            TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b"),
            TrajectoryEntry(entry_type=TOOL_CALL, content="c"),
        ]
        t = Trajectory.from_replay(entries, replay_until=2)
        snap = t.snapshot()
        assert len(snap) == 2
        assert snap[0].content == "a"
        assert snap[1].content == "b"
```

**Step 2: Run to verify fail**

**Step 3: Implement**

```python
# src/superred/types/trajectory.py
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from superred.types.feedback import FeedbackResult
from superred.types.security import SecurityDomainTag


@dataclass(frozen=True)
class TrajectoryEntryType:
    name: str
    actor: str
    content_type: type


MODEL_REQUEST = TrajectoryEntryType("model_request", "target", str)
MODEL_RESPONSE = TrajectoryEntryType("model_response", "llm", str)
TOOL_CALL = TrajectoryEntryType("tool_call", "target", str)
TOOL_RESULT = TrajectoryEntryType("tool_result", "tool", str)
INJECTION = TrajectoryEntryType("injection", "optimizer", str)
FEEDBACK = TrajectoryEntryType("feedback", "evaluator", FeedbackResult)


@dataclass
class TrajectoryEntry:
    entry_type: TrajectoryEntryType
    content: Any
    timestamp: datetime = field(default_factory=datetime.now)
    security_domain: SecurityDomainTag | None = None
    parent_id: str | None = None


class Trajectory:
    """Async-safe, append-only trajectory stream."""

    def __init__(self) -> None:
        self._entries: list[TrajectoryEntry] = []
        self._cursor: int = 0
        self._closed: bool = False
        self._lock: asyncio.Lock = asyncio.Lock()

    async def emit(self, entry: TrajectoryEntry) -> None:
        async with self._lock:
            if self._closed:
                raise RuntimeError("Cannot emit to a closed trajectory")
            self._entries.append(entry)

    def close(self) -> None:
        self._closed = True

    def snapshot(self) -> list[TrajectoryEntry]:
        return list(self._entries)

    async def drain(self) -> list[TrajectoryEntry]:
        async with self._lock:
            new = self._entries[self._cursor:]
            self._cursor = len(self._entries)
            return new

    def __len__(self) -> int:
        return len(self._entries)

    @classmethod
    def from_replay(
        cls, entries: list[TrajectoryEntry], replay_until: int
    ) -> Trajectory:
        t = cls()
        t._entries = list(entries[:replay_until])
        t._cursor = 0
        return t
```

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add src/superred/types/trajectory.py tests/test_types/test_trajectory.py
git commit -m "feat: add async-safe Trajectory with replay support"
```

---

### Task 5: Types — Budget Hierarchy & Claims

**Files:**
- Create: `src/superred/types/budget.py`
- Create: `src/superred/types/claim.py`
- Test: `tests/test_types/test_budget.py`
- Test: `tests/test_types/test_claim.py`

**Step 1: Write the failing tests**

```python
# tests/test_types/test_budget.py
import pytest
from superred.types.budget import Budget, BudgetUsage, HierarchicalBudget


class TestBudget:
    def test_all_none_by_default(self):
        b = Budget()
        assert b.max_iterations is None

    def test_specific_limits(self):
        b = Budget(max_iterations=25, max_cost_usd=5.0)
        assert b.max_iterations == 25


class TestBudgetUsage:
    def test_defaults_zero(self):
        u = BudgetUsage()
        assert u.iterations == 0
        assert u.tokens == 0

    def test_mutable(self):
        u = BudgetUsage()
        u.iterations = 5
        assert u.iterations == 5


class TestHierarchicalBudget:
    def test_root_creation(self):
        b = Budget(max_iterations=10, max_tokens=1000)
        hb = HierarchicalBudget(budget=b)
        assert not hb.exhausted

    def test_record_usage(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=2))
        hb.record(iterations=1)
        assert not hb.exhausted
        hb.record(iterations=1)
        assert hb.exhausted

    def test_allocate_child(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=10))
        child = hb.allocate(fraction=0.5)
        assert child._budget.max_iterations == 5

    def test_child_usage_propagates(self):
        hb = HierarchicalBudget(budget=Budget(max_tokens=100))
        child = hb.allocate(fraction=0.5)
        child.record(tokens=30)
        assert hb.usage.tokens == 30

    def test_child_cannot_exceed_parent(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=10))
        child = hb.allocate(fraction=0.3)  # 3 iterations
        child.record(iterations=3)
        assert child.exhausted

    def test_remaining(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=10, max_tokens=1000))
        hb.record(iterations=3, tokens=200)
        r = hb.remaining
        assert r.max_iterations == 7
        assert r.max_tokens == 800
```

```python
# tests/test_types/test_claim.py
from superred.types.claim import (
    PropertyKind, ClaimVerdict, OracleEvidence, ContextSnapshot, OracleBundle,
)
from superred.types.goal import Goal


class TestPropertyKind:
    def test_four_families(self):
        assert len(PropertyKind) == 4
        assert PropertyKind.DATA_ISOLATION.name == "DATA_ISOLATION"


class TestClaimVerdict:
    def test_verdict_fields(self):
        v = ClaimVerdict(
            property_kind=PropertyKind.DATA_ISOLATION,
            satisfied=False,
            confidence=0.95,
            evidence=[OracleEvidence(name="leak", value="secret123", confidence=1.0)],
            explanation="Secret found in external output",
        )
        assert not v.satisfied
        assert v.evidence[0].value == "secret123"


class TestOracleBundle:
    def test_bundle(self):
        ob = OracleBundle(
            ground_truth_output="Rome",
            forbidden_actions=["transfer_money"],
            sensitive_data={"api_key": "sk-xxx"},
            source_attribution={"instruction_1": "user"},
        )
        assert ob.sensitive_data["api_key"] == "sk-xxx"


class TestContextSnapshot:
    def test_snapshot(self):
        cs = ContextSnapshot(
            goal=Goal(description="test"),
            trajectory_entries=[],
            task_config={"system_prompt": "You are helpful"},
        )
        assert cs.task_config["system_prompt"] == "You are helpful"
```

**Step 2: Run to verify fail**

**Step 3: Implement**

```python
# src/superred/types/budget.py
from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Budget:
    max_iterations: int | None = None
    max_model_calls: int | None = None
    max_tokens: int | None = None
    max_wall_seconds: float | None = None
    max_cost_usd: float | None = None


@dataclass
class BudgetUsage:
    iterations: int = 0
    model_calls: int = 0
    tokens: int = 0
    wall_seconds: float = 0.0
    cost_usd: float = 0.0


class HierarchicalBudget:
    """Tree-structured budget. Children report usage upward."""

    def __init__(
        self,
        budget: Budget,
        parent: HierarchicalBudget | None = None,
    ) -> None:
        self._budget = budget
        self._parent = parent
        self._usage = BudgetUsage()

    @property
    def usage(self) -> BudgetUsage:
        return self._usage

    @property
    def remaining(self) -> Budget:
        def _rem(limit: int | None, used: int) -> int | None:
            return None if limit is None else max(0, limit - used)

        def _rem_f(limit: float | None, used: float) -> float | None:
            return None if limit is None else max(0.0, limit - used)

        return Budget(
            max_iterations=_rem(self._budget.max_iterations, self._usage.iterations),
            max_model_calls=_rem(self._budget.max_model_calls, self._usage.model_calls),
            max_tokens=_rem(self._budget.max_tokens, self._usage.tokens),
            max_wall_seconds=_rem_f(self._budget.max_wall_seconds, self._usage.wall_seconds),
            max_cost_usd=_rem_f(self._budget.max_cost_usd, self._usage.cost_usd),
        )

    @property
    def exhausted(self) -> bool:
        b, u = self._budget, self._usage
        if b.max_iterations is not None and u.iterations >= b.max_iterations:
            return True
        if b.max_model_calls is not None and u.model_calls >= b.max_model_calls:
            return True
        if b.max_tokens is not None and u.tokens >= b.max_tokens:
            return True
        if b.max_wall_seconds is not None and u.wall_seconds >= b.max_wall_seconds:
            return True
        if b.max_cost_usd is not None and u.cost_usd >= b.max_cost_usd:
            return True
        return False

    def record(self, **kwargs: int | float) -> None:
        for key, val in kwargs.items():
            current = getattr(self._usage, key)
            setattr(self._usage, key, current + val)
        if self._parent is not None:
            self._parent.record(**kwargs)

    def allocate(self, fraction: float) -> HierarchicalBudget:
        def _scale_int(v: int | None) -> int | None:
            return None if v is None else max(1, math.floor(v * fraction))

        def _scale_float(v: float | None) -> float | None:
            return None if v is None else v * fraction

        child_budget = Budget(
            max_iterations=_scale_int(self._budget.max_iterations),
            max_model_calls=_scale_int(self._budget.max_model_calls),
            max_tokens=_scale_int(self._budget.max_tokens),
            max_wall_seconds=_scale_float(self._budget.max_wall_seconds),
            max_cost_usd=_scale_float(self._budget.max_cost_usd),
        )
        return HierarchicalBudget(budget=child_budget, parent=self)
```

```python
# src/superred/types/claim.py
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable

from superred.types.goal import Goal

if TYPE_CHECKING:
    from superred.types.trajectory import TrajectoryEntry


class PropertyKind(Enum):
    TASK_ALIGNMENT = "task_alignment"
    ACTION_ALIGNMENT = "action_alignment"
    AUTHORIZED_INSTRUCTION_FOLLOWING = "authorized_instruction_following"
    DATA_ISOLATION = "data_isolation"


@dataclass(frozen=True)
class OracleEvidence:
    name: str
    value: str
    confidence: float
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ClaimVerdict:
    property_kind: PropertyKind
    satisfied: bool
    confidence: float
    evidence: list[OracleEvidence]
    explanation: str


@dataclass(frozen=True)
class ContextSnapshot:
    goal: Goal
    trajectory_entries: list[TrajectoryEntry]
    task_config: dict[str, str]


@dataclass(frozen=True)
class OracleBundle:
    ground_truth_output: str | None = None
    forbidden_actions: list[str] = field(default_factory=list)
    sensitive_data: dict[str, str] = field(default_factory=dict)
    source_attribution: dict[str, str] = field(default_factory=dict)


ClaimPredicate = Callable[[ContextSnapshot, OracleBundle], ClaimVerdict]
```

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add src/superred/types/budget.py src/superred/types/claim.py \
        tests/test_types/test_budget.py tests/test_types/test_claim.py
git commit -m "feat: add HierarchicalBudget, ClaimPredicate, OracleBundle types"
```

---

### Task 6: Types — `__init__.py` re-exports

**Files:**
- Modify: `src/superred/types/__init__.py`

**Step 1: Write the failing test**

```python
# tests/test_types/test_init.py
def test_types_reexports():
    """All core types importable from superred.types."""
    from superred.types import (
        SecurityDomainTag, SecurityDomain, ThreatModel, Budget,
        Event, EventResponse, ControllablePreCallEvent, ControllableInjection,
        PassThrough, OptimizerDoneEvent,
        ControllableSpec, Controllable, RequestAnswerPair,
        Observable, ObservableValue,
        Goal,
        ConfigSpec, StateSpec, RuntimeParamSpec,
        Score, EvaluationResult, FeedbackResult,
        Trajectory, TrajectoryEntry, TrajectoryEntryType,
        MODEL_REQUEST, MODEL_RESPONSE, TOOL_CALL, TOOL_RESULT, INJECTION, FEEDBACK,
        BudgetUsage, HierarchicalBudget,
        PropertyKind, ClaimVerdict, OracleEvidence, ContextSnapshot, OracleBundle,
    )
```

**Step 2: Run to verify fail**

**Step 3: Implement** — Write `src/superred/types/__init__.py` that re-exports everything from each submodule with an `__all__` list.

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add src/superred/types/__init__.py tests/test_types/test_init.py
git commit -m "feat: add types package re-exports"
```

---

### Task 7: Channels — Channel, AsyncSender, AsyncReceiver

**Files:**
- Create: `src/superred/channels/channel.py`
- Test: `tests/test_channels/test_channel.py`

**Step 1: Write the failing tests**

```python
# tests/test_channels/test_channel.py
import pytest
import asyncio
from superred.channels.channel import channel, AsyncSender, AsyncReceiver, Channel, ChannelClosed


class TestChannel:
    @pytest.mark.asyncio
    async def test_send_recv(self):
        ch = channel[str]()
        await ch.sender.send("hello")
        msg = await ch.receiver.recv()
        assert msg == "hello"

    @pytest.mark.asyncio
    async def test_recv_nowait_empty(self):
        ch = channel[str]()
        result = ch.receiver.recv_nowait()
        assert result is None

    @pytest.mark.asyncio
    async def test_recv_nowait_has_item(self):
        ch = channel[str]()
        await ch.sender.send("x")
        result = ch.receiver.recv_nowait()
        assert result == "x"

    @pytest.mark.asyncio
    async def test_close_ends_iteration(self):
        ch = channel[int]()
        await ch.sender.send(1)
        await ch.sender.send(2)
        ch.sender.close()

        items = []
        async for item in ch.receiver:
            items.append(item)
        assert items == [1, 2]

    @pytest.mark.asyncio
    async def test_send_after_close_raises(self):
        ch = channel[str]()
        ch.sender.close()
        with pytest.raises(ChannelClosed):
            await ch.sender.send("x")

    @pytest.mark.asyncio
    async def test_buffered_channel(self):
        ch = channel[int](buffer=2)
        await ch.sender.send(1)
        await ch.sender.send(2)
        # Both sent without blocking since buffer=2
        assert await ch.receiver.recv() == 1
        assert await ch.receiver.recv() == 2

    @pytest.mark.asyncio
    async def test_concurrent_send_recv(self):
        ch = channel[int]()
        results = []

        async def producer():
            for i in range(5):
                await ch.sender.send(i)
            ch.sender.close()

        async def consumer():
            async for item in ch.receiver:
                results.append(item)

        await asyncio.gather(producer(), consumer())
        assert results == [0, 1, 2, 3, 4]
```

**Step 2: Run to verify fail**

**Step 3: Implement**

```python
# src/superred/channels/channel.py
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Generic, TypeVar, Self

T = TypeVar("T")

_SENTINEL = object()


class ChannelClosed(Exception):
    """Raised when sending to a closed channel."""


class AsyncSender(Generic[T]):
    """Write end of a channel."""

    def __init__(self, queue: asyncio.Queue[T | object]) -> None:
        self._queue = queue
        self._closed = False

    async def send(self, item: T) -> None:
        if self._closed:
            raise ChannelClosed("Cannot send to a closed channel")
        await self._queue.put(item)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._queue.put_nowait(_SENTINEL)


class AsyncReceiver(Generic[T]):
    """Read end of a channel. Supports async iteration."""

    def __init__(self, queue: asyncio.Queue[T | object]) -> None:
        self._queue = queue

    async def recv(self) -> T:
        item = await self._queue.get()
        if item is _SENTINEL:
            raise StopAsyncIteration
        return item  # type: ignore[return-value]

    def recv_nowait(self) -> T | None:
        try:
            item = self._queue.get_nowait()
        except asyncio.QueueEmpty:
            return None
        if item is _SENTINEL:
            return None
        return item  # type: ignore[return-value]

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> T:
        item = await self._queue.get()
        if item is _SENTINEL:
            raise StopAsyncIteration
        return item  # type: ignore[return-value]


@dataclass
class Channel(Generic[T]):
    """A typed, buffered, async pipe."""

    sender: AsyncSender[T]
    receiver: AsyncReceiver[T]


def channel(buffer: int = 0) -> Channel:
    """Create a channel pair. buffer=0 means unbounded."""
    maxsize = buffer if buffer > 0 else 0
    q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
    return Channel(sender=AsyncSender(q), receiver=AsyncReceiver(q))
```

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add src/superred/channels/channel.py tests/test_channels/test_channel.py
git commit -m "feat: add Channel, AsyncSender, AsyncReceiver with async iteration"
```

---

### Task 8: Channels — Middleware & compose()

**Files:**
- Create: `src/superred/channels/middleware.py`
- Test: `tests/test_channels/test_middleware.py`

**Step 1: Write the failing tests**

```python
# tests/test_channels/test_middleware.py
import pytest
import asyncio
from superred.channels.channel import channel, Channel
from superred.channels.middleware import (
    Middleware, compose, trace_recorder, threat_model_filter, budget_enforcer, logger_middleware,
)
from superred.types.event import Event, ControllablePreCallEvent
from superred.types.security import SecurityDomainTag, ThreatModel, Budget
from superred.types.controllable import ControllableSpec
from superred.types.trajectory import Trajectory
from superred.types.budget import HierarchicalBudget


class TestCompose:
    @pytest.mark.asyncio
    async def test_identity(self):
        """No middleware = pass-through."""
        ch = channel[str]()
        composed = compose()(ch)
        await composed.sender.send("hello")
        composed.sender.close()
        items = [item async for item in composed.receiver]
        assert items == ["hello"]


class TestTraceRecorder:
    @pytest.mark.asyncio
    async def test_records_events(self):
        traj = Trajectory()
        ch = channel[Event]()
        wrapped = trace_recorder(traj)(ch)

        tag = SecurityDomainTag(name="user")
        spec = ControllableSpec(name="input", security_domain=tag)
        event = ControllablePreCallEvent(
            controllable=spec, request="test", security_domain=tag,
        )
        await wrapped.sender.send(event)
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]  # drain
        # Give recorder task time to process
        await asyncio.sleep(0.01)
        assert len(traj) >= 1


class TestThreatModelFilter:
    @pytest.mark.asyncio
    async def test_passes_allowed_domain(self):
        tm = ThreatModel(
            name="user_only",
            controllables=frozenset({"input"}),
            observables=frozenset(),
            feedback=frozenset(),
            budget=Budget(),
        )
        ch = channel[Event]()
        wrapped = threat_model_filter(tm)(ch)

        tag = SecurityDomainTag(name="user")
        event = Event(security_domain=tag)
        await wrapped.sender.send(event)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 1

    @pytest.mark.asyncio
    async def test_drops_disallowed_domain(self):
        tm = ThreatModel(
            name="user_only",
            controllables=frozenset({"user_input"}),
            observables=frozenset(),
            feedback=frozenset(),
            budget=Budget(),
        )
        ch = channel[Event]()
        wrapped = threat_model_filter(tm)(ch)

        tag = SecurityDomainTag(name="internal")
        event = Event(security_domain=tag)
        await wrapped.sender.send(event)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 0


class TestBudgetEnforcer:
    @pytest.mark.asyncio
    async def test_closes_on_exhaustion(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=2))
        ch = channel[Event]()
        wrapped = budget_enforcer(hb)(ch)

        for _ in range(3):
            await wrapped.sender.send(Event())

        wrapped.sender.close()
        items = [item async for item in wrapped.receiver]
        # Should have closed after 2
        assert len(items) <= 2
```

**Step 2: Run to verify fail**

**Step 3: Implement** — Each middleware follows the same pattern: create a new channel, spawn a background task that reads from inner→processes→writes to outer. `compose()` chains them. `threat_model_filter` checks `event.security_domain.name` against the ThreatModel's combined `controllables | observables | feedback` sets. `budget_enforcer` calls `hb.record(iterations=1)` per event and closes when exhausted.

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add src/superred/channels/middleware.py tests/test_channels/test_middleware.py
git commit -m "feat: add middleware compose, trace_recorder, threat_filter, budget_enforcer"
```

---

### Task 9: Channels — EventBus

**Files:**
- Create: `src/superred/channels/bus.py`
- Test: `tests/test_channels/test_bus.py`

**Step 1: Write the failing tests**

```python
# tests/test_channels/test_bus.py
import pytest
import asyncio
from superred.channels.bus import EventBus


class TestEventBus:
    @pytest.mark.asyncio
    async def test_single_subscriber(self):
        bus = EventBus[str]()
        rx = bus.subscribe()
        await bus.publish("hello")
        bus.close()
        items = [item async for item in rx]
        assert items == ["hello"]

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self):
        bus = EventBus[int]()
        rx1 = bus.subscribe()
        rx2 = bus.subscribe()
        await bus.publish(42)
        bus.close()

        items1 = [item async for item in rx1]
        items2 = [item async for item in rx2]
        assert items1 == [42]
        assert items2 == [42]

    @pytest.mark.asyncio
    async def test_close_ends_all(self):
        bus = EventBus[str]()
        rx1 = bus.subscribe()
        rx2 = bus.subscribe()
        bus.close()
        assert [item async for item in rx1] == []
        assert [item async for item in rx2] == []
```

**Step 2: Run to verify fail**

**Step 3: Implement** — `EventBus` maintains a list of `AsyncSender` instances. `subscribe()` creates a `channel()`, stores the sender, returns the receiver. `publish()` sends to all senders. `close()` closes all senders.

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add src/superred/channels/bus.py tests/test_channels/test_bus.py
git commit -m "feat: add EventBus for fan-out broadcasting"
```

---

### Task 10: Interfaces — Target, Task, Optimizer, Judge, SecurityClaim

**Files:**
- Create: `src/superred/interfaces/target.py`
- Create: `src/superred/interfaces/task.py`
- Create: `src/superred/interfaces/optimizer.py`
- Create: `src/superred/interfaces/judge.py`
- Create: `src/superred/interfaces/security_claim.py`
- Test: `tests/test_interfaces/test_abcs.py`

**Step 1: Write the failing tests**

```python
# tests/test_interfaces/test_abcs.py
import pytest
import asyncio
from superred.interfaces.target import Target
from superred.interfaces.task import Task, NotApplicable
from superred.interfaces.optimizer import Optimizer
from superred.interfaces.judge import Judge
from superred.interfaces.security_claim import SecurityClaim
from superred.types import (
    Goal, Event, EventResponse, PassThrough, ControllableSpec, Controllable,
    Observable, ObservableValue, ConfigSpec, StateSpec, RuntimeParamSpec,
    Trajectory, TrajectoryEntry, MODEL_REQUEST, EvaluationResult, Score,
    OracleBundle, SecurityDomainTag, OptimizerDoneEvent,
)
from superred.types.budget import HierarchicalBudget, Budget
from superred.channels.channel import AsyncSender, AsyncReceiver


class StubTarget(Target):
    def controllable_specs(self): return []
    def observable_specs(self): return []
    def config_specs(self): return []
    def state_specs(self): return []
    def runtime_params(self): return []
    async def set_config(self, name, value): pass
    async def get_observables(self): return []
    async def run(self, send_event, recv_response): pass
    async def get_state(self, name): return ""


class StubTask(Task[StubTarget]):
    @property
    def goal(self): return Goal(description="test")
    async def configure(self, target): return {}
    async def evaluate(self, trajectory, target):
        return EvaluationResult(success=False, primary_score=Score(value=0.0))
    def oracle_bundle(self): return OracleBundle()


class StubOptimizer(Optimizer):
    async def initialize(self, goal, controllables, observables, budget): pass
    async def on_event(self, event): return None


class StubJudge(Judge):
    async def evaluate(self, goal, trajectory, oracle):
        return EvaluationResult(success=True, primary_score=Score(value=1.0))


class TestTarget:
    def test_instantiate(self):
        t = StubTarget()
        assert t.max_concurrent_runs == 1

    @pytest.mark.asyncio
    async def test_lifecycle(self):
        t = StubTarget()
        await t.setup()
        await t.teardown()


class TestTask:
    def test_goal(self):
        task = StubTask()
        assert task.goal.description == "test"


class TestOptimizer:
    @pytest.mark.asyncio
    async def test_run_loop_passthrough(self):
        """on_event returning None should produce PassThrough on response channel."""
        opt = StubOptimizer()
        await opt.initialize(
            Goal(description="test"), [], [],
            HierarchicalBudget(budget=Budget()),
        )
        event = Event()
        resp = await opt.on_event(event)
        assert resp is None  # base class doesn't touch this; _run_loop does


class TestSecurityClaim:
    def test_from_tasks_iterable(self):
        t1 = StubTask()
        t2 = StubTask()
        claim = SecurityClaim.from_tasks([t1, t2])
        tasks = list(claim)
        assert len(tasks) == 2

    def test_from_claims_lazy_chain(self):
        c1 = SecurityClaim.from_tasks([StubTask()])
        c2 = SecurityClaim.from_tasks([StubTask(), StubTask()])
        combined = SecurityClaim.from_claims([c1, c2])
        assert len(list(combined)) == 3

    def test_re_iterable(self):
        claim = SecurityClaim.from_tasks([StubTask()])
        assert len(list(claim)) == len(list(claim))
```

**Step 2: Run to verify fail**

**Step 3: Implement** all five interface files. Key points:
- `Target`: ABCs with default no-op `setup()`/`teardown()`, `max_concurrent_runs` property returning 1.
- `Task[T_Target]`: Generic with `TypeVar("T_Target", bound=Target)`. `NotApplicable` exception.
- `Optimizer`: ABC with `_on_run_start(trajectory)`, `_on_run_end()`, `_run_loop(event_rx, response_tx)` on the base class. `current_trajectory`, `past_trajectories` as instance state.
- `Judge`: Single abstract `evaluate()` method.
- `SecurityClaim`: Concrete generic container with `from_tasks`, `from_claims`, `__iter__`.

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add src/superred/interfaces/ tests/test_interfaces/test_abcs.py
git commit -m "feat: add Target, Task, Optimizer, Judge, SecurityClaim interfaces"
```

---

### Task 11: Interfaces — Optimizer `_run_loop` integration test

**Files:**
- Test: `tests/test_interfaces/test_optimizer_loop.py`

This tests that the optimizer's `_run_loop` correctly reads events from a channel, calls `on_event`, and writes responses (or PassThrough) to the response channel. This validates the core channel-graph wiring pattern.

**Step 1: Write the failing test**

```python
# tests/test_interfaces/test_optimizer_loop.py
import pytest
import asyncio
from superred.interfaces.optimizer import Optimizer
from superred.types import (
    Goal, Event, EventResponse, ControllableInjection, PassThrough,
    ControllablePreCallEvent, ControllableSpec, SecurityDomainTag,
    Trajectory, OptimizerDoneEvent,
)
from superred.types.budget import HierarchicalBudget, Budget
from superred.channels.channel import channel


class InjectingOptimizer(Optimizer):
    async def initialize(self, goal, controllables, observables, budget):
        pass

    async def on_event(self, event):
        if isinstance(event, ControllablePreCallEvent):
            return ControllableInjection(event=event, value="INJECTED")
        return None  # pass-through for other events


class TestRunLoop:
    @pytest.mark.asyncio
    async def test_injection_response(self):
        opt = InjectingOptimizer()
        await opt.initialize(
            Goal(description="test"), [], [],
            HierarchicalBudget(budget=Budget()),
        )
        traj = Trajectory()
        opt._on_run_start(traj)

        event_ch = channel[Event]()
        response_ch = channel[EventResponse]()

        loop_task = asyncio.create_task(
            opt._run_loop(event_ch.receiver, response_ch.sender)
        )

        tag = SecurityDomainTag(name="user")
        spec = ControllableSpec(name="input", security_domain=tag)
        await event_ch.sender.send(
            ControllablePreCallEvent(controllable=spec, request="hello", security_domain=tag)
        )
        resp = await response_ch.receiver.recv()
        assert isinstance(resp, ControllableInjection)
        assert resp.value == "INJECTED"

        # Send a plain event — should get PassThrough
        await event_ch.sender.send(Event())
        resp2 = await response_ch.receiver.recv()
        assert isinstance(resp2, PassThrough)

        event_ch.sender.close()
        await loop_task

    @pytest.mark.asyncio
    async def test_history_tracking(self):
        opt = InjectingOptimizer()
        await opt.initialize(
            Goal(description="test"), [], [],
            HierarchicalBudget(budget=Budget()),
        )
        traj = Trajectory()
        opt._on_run_start(traj)
        assert opt.current_trajectory is traj
        assert len(opt.past_trajectories) == 0

        done = opt._on_run_end()
        assert opt.current_trajectory is None
        assert len(opt.past_trajectories) == 1
```

**Step 2: Run to verify fail**

**Step 3: If `_run_loop` isn't implemented yet, add it to the Optimizer base class (from Task 10). It should be a simple loop:**

```python
async def _run_loop(
    self,
    event_rx: AsyncReceiver[Event],
    response_tx: AsyncSender[EventResponse],
) -> None:
    async for event in event_rx:
        response = await self.on_event(event)
        if response is not None:
            await response_tx.send(response)
        else:
            await response_tx.send(PassThrough(event=event))
```

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git add tests/test_interfaces/test_optimizer_loop.py src/superred/interfaces/optimizer.py
git commit -m "test: add optimizer _run_loop integration test with channel wiring"
```

---

### Task 12: Package re-exports & `__init__.py`

**Files:**
- Modify: `src/superred/types/__init__.py` (if not done in Task 6)
- Create: `src/superred/interfaces/__init__.py`
- Create: `src/superred/channels/__init__.py`
- Modify: `src/superred/__init__.py`

**Step 1: Write the test**

```python
# tests/test_init.py
def test_top_level_imports():
    from superred import (
        Target, Task, Optimizer, Judge, SecurityClaim,
        Event, EventResponse, Goal, Trajectory,
    )

def test_channel_imports():
    from superred.channels import channel, Channel, compose, EventBus
```

**Step 2–5: Implement and commit.**

```bash
git commit -m "feat: add package-level re-exports"
```

---

### Task 13: Controller — Core evaluation loop

**Files:**
- Create: `src/superred/controller/results.py`
- Create: `src/superred/controller/controller.py`
- Test: `tests/test_controller/test_controller.py`

This is the biggest single task. The controller wires channels, runs the concurrent target+optimizer loop, and collects results.

**Step 1: Write the failing test** — Use stub target, task, and optimizer. Verify that:
- The controller runs one iteration
- Events flow from target → middleware → optimizer
- Responses flow back
- EvaluationResult is collected into RunResult
- Budget is tracked

**Step 2: Run to verify fail**

**Step 3: Implement** `results.py` (RunResult, TaskResult, EvalResult with metric methods) and `controller.py` (the core loop from design doc Section 7).

**Step 4: Run tests — all PASS**

**Step 5: Commit**

```bash
git commit -m "feat: add Controller with core evaluation loop"
```

---

### Task 14: Controller — Threat model sweep

**Files:**
- Create: `src/superred/controller/threat_sweep.py`
- Test: `tests/test_controller/test_threat_sweep.py`

**Step 1: Test** that `ThreatModelSweeper` takes a target's specs and generates a family of ThreatModels ordered narrowest→widest.

**Step 3: Implement** — Uses `SecurityDomain.distinct_combinations()` to generate tag sets, then builds a `ThreatModel` for each, filtering controllable/observable/feedback specs by tag membership.

**Step 5: Commit**

```bash
git commit -m "feat: add ThreatModelSweeper for automatic threat model generation"
```

---

### Task 15: Proxies — LLM Proxy middleware

**Files:**
- Create: `src/superred/proxies/llm_proxy.py`
- Test: `tests/test_proxies/test_llm_proxy.py`

**Step 1: Test** that the LLM proxy middleware:
- Passes events through
- Records MODEL_REQUEST/MODEL_RESPONSE events to the trajectory
- Tracks token counts on the HierarchicalBudget

**Step 3: Implement** as a middleware factory that returns `Middleware[Event]`.

**Step 5: Commit**

```bash
git commit -m "feat: add LLM proxy middleware for model call interception"
```

---

### Task 16: Proxies — Tool Proxy middleware

**Files:**
- Create: `src/superred/proxies/tool_proxy.py`
- Test: `tests/test_proxies/test_tool_proxy.py`

**Step 1: Test** that tool proxy records ControllablePreCall/PostCall events to trajectory.

**Step 5: Commit**

```bash
git commit -m "feat: add Tool proxy middleware for tool call interception"
```

---

### Task 17: Proxies — Replay Proxy for staged running

**Files:**
- Create: `src/superred/proxies/replay.py`
- Create: `src/superred/controller/stage.py`
- Test: `tests/test_proxies/test_replay.py`

**Step 1: Test** that:
- Events before checkpoint return recorded responses immediately
- Events at/past checkpoint flow through live
- `ReplayDivergenceError` raised on mismatch

**Step 3: Implement** replay proxy + `StagedRunner` helper.

**Step 5: Commit**

```bash
git commit -m "feat: add ReplayProxy and StagedRunner for staged running"
```

---

### Task 18: Security Claims — Built-in predicates

**Files:**
- Create: `src/superred/claims/predicates.py`
- Test: `tests/test_claims/test_predicates.py`

Create `src/superred/claims/__init__.py` and `tests/test_claims/__init__.py`.

**Step 1: Test** each of the four built-in predicates:
- `task_alignment_claim`: checks if trajectory deviates from goal
- `action_alignment_claim`: checks if forbidden actions were taken
- `authorized_instruction_following_claim`: checks source attribution
- `data_isolation_claim`: checks if sensitive data leaked across domains

**Step 3: Implement** as plain functions matching `ClaimPredicate` signature.

**Step 5: Commit**

```bash
git commit -m "feat: add built-in security claim predicates"
```

---

### Task 19: Judges — FunctionJudge, RegexJudge, LLMJudge

**Files:**
- Create: `src/superred/judges/function_judge.py`
- Create: `src/superred/judges/regex_judge.py`
- Create: `src/superred/judges/llm_judge.py`
- Test: `tests/test_judges/test_judges.py`

Create `src/superred/judges/__init__.py` and `tests/test_judges/__init__.py`.

**Step 1: Test** FunctionJudge with a lambda, RegexJudge with a pattern. LLMJudge can be tested with a mock LLM call.

**Step 5: Commit**

```bash
git commit -m "feat: add FunctionJudge, RegexJudge, LLMJudge implementations"
```

---

### Task 20: Registry — Plugin discovery

**Files:**
- Create: `src/superred/registry/discovery.py`
- Test: `tests/test_registry/test_discovery.py`

**Step 1: Test** that `Registry.discover_optimizers()` finds entry points. Use `importlib.metadata` mock or register a test entry point.

**Step 5: Commit**

```bash
git commit -m "feat: add plugin registry with entry-point discovery"
```

---

### Task 21: CLI — Config loading & commands

**Files:**
- Create: `src/superred/cli/config.py`
- Create: `src/superred/cli/main.py`
- Test: `tests/test_cli/test_config.py`
- Test: `tests/test_cli/test_cli.py`

**Step 1: Test** YAML config loading produces correct target/optimizer/task/threat_model config objects. Test CLI commands with Click's `CliRunner`.

**Step 3: Implement** — `config.py` loads YAML, validates structure, resolves module names via registry. `main.py` defines Click commands: `run`, `sweep`, `list`, `export`.

**Step 5: Commit**

```bash
git commit -m "feat: add CLI with run, sweep, list, export commands"
```

---

### Task 22: Integration test — End-to-end with stubs

**Files:**
- Test: `tests/test_integration/test_e2e.py`

Create `tests/test_integration/__init__.py`.

**Step 1: Write the test**

```python
# tests/test_integration/test_e2e.py
import pytest
import asyncio
from superred.controller.controller import Controller
from superred.types import *
from superred.types.budget import Budget
# ... import stub target, task, optimizer from test_interfaces/test_abcs.py
# or define local stubs

class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_single_run_produces_result(self):
        """Full loop: controller → target ↔ optimizer → evaluate → RunResult."""
        # Create stub target that emits one ControllablePreCallEvent
        # Create stub optimizer that injects
        # Create stub task that evaluates success
        # Run controller.evaluate_single(target, task, optimizer, threat_model)
        # Assert RunResult has evaluation, trajectory, budget_used
        pass

    @pytest.mark.asyncio
    async def test_threat_model_sweep(self):
        """Sweep produces results keyed by threat model."""
        pass
```

Fill in with concrete stubs. This validates the entire channel-graph wiring end-to-end.

**Step 5: Commit**

```bash
git commit -m "test: add end-to-end integration test with stub components"
```

---

### Task 23: Update pyproject.toml & top-level __init__.py

**Files:**
- Modify: `src/superred/__init__.py` — final public API re-exports
- Modify: `pyproject.toml` — entry points for built-in judges/claims

**Step 5: Commit**

```bash
git commit -m "chore: finalize package exports and entry points"
```

---

## Task Dependency Graph

```
Prerequisites (scaffold + pyproject.toml)
    │
    ├── Task 1: security.py
    │       │
    ├── Task 3: controllable, observable, goal, config, feedback
    │       │
    │       └── Task 2: event.py (depends on controllable.py)
    │               │
    │               └── Task 4: trajectory.py
    │
    ├── Task 5: budget.py, claim.py
    │
    └── Task 6: types __init__.py
            │
            ├── Task 7: channel.py
            │       │
            │       ├── Task 8: middleware.py
            │       │       │
            │       │       ├── Task 15: llm_proxy
            │       │       ├── Task 16: tool_proxy
            │       │       └── Task 17: replay_proxy + staged runner
            │       │
            │       └── Task 9: bus.py
            │
            ├── Task 10: interfaces (Target, Task, Optimizer, Judge, SecurityClaim)
            │       │
            │       └── Task 11: optimizer _run_loop integration test
            │
            └── Task 12: package re-exports
                    │
                    ├── Task 13: controller core loop
                    │       │
                    │       └── Task 14: threat model sweep
                    │
                    ├── Task 18: claim predicates
                    ├── Task 19: judges
                    ├── Task 20: registry
                    │       │
                    │       └── Task 21: CLI
                    │
                    └── Task 22: integration test
                            │
                            └── Task 23: finalize
```

Tasks on the same level with no arrow between them can be implemented in parallel.
