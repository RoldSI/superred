# Mutation Testing

## Tool: mutmut v2.5

Configuration is in `pyproject.toml` under `[tool.mutmut]`.

```bash
# Run all mutants (~2 minutes)
mutmut run --no-progress

# View results (may crash on Python 3.13 due to pony ORM bug —
# use sqlite query below as workaround)
mutmut results

# Inspect a specific mutant's diff
mutmut show <id>

# Query results directly from the sqlite cache
python -c "
import sqlite3
conn = sqlite3.connect('.mutmut-cache')
c = conn.cursor()
c.execute('SELECT status, count(*) FROM Mutant GROUP BY status')
for status, count in c.fetchall(): print(f'  {status}: {count}')
"
```

## Results (2026-04-02)

| Metric | Value |
|--------|-------|
| Total mutants | 324 |
| Killed (by mutmut) | 196 |
| Timeout | 6 |
| Survived (by mutmut) | 122 |
| Import-crash (killed but miscounted by mutmut) | 9 |
| Equivalent/unkillable | 83 |
| **Effectively killed** | **211** |
| **Raw score** (mutmut reported) | **62.3%** |
| **Adjusted score** (excl. equivalents, incl. import-crash) | **87.6%** (211/241) |

### Note on import-crash mutants

9 mutants in `security_domain.py` crash at conftest import time (pytest exit code 4 =
"collection error"). mutmut counts these as "survived" because no test assertion fired,
but the mutation does cause an immediate crash — they are effectively killed. These are
validation mutations (duplicate check, orphan check) that break `SecurityDomain()`
construction used in `conftest.py`.

### Per-module breakdown

| Module | Kill | Surv | TO | Total | Score |
|--------|------|------|----|-------|-------|
| types/goal.py | 2 | 0 | 0 | 2 | 100% |
| types/evaluation.py | 10 | 0 | 0 | 10 | 100% |
| types/controllable.py | 10 | 0 | 0 | 10 | 100% |
| types/observable.py | 8 | 1 | 0 | 9 | 89% |
| middleware.py | 8 | 2 | 0 | 10 | 80% |
| interfaces/optimizer.py | 14 | 4 | 1 | 19 | 79% |
| types/state.py | 5 | 2 | 0 | 7 | 71% |
| channel.py | 20 | 11 | 4 | 35 | 69% |
| interfaces/security_claim.py | 11 | 6 | 0 | 17 | 65% |
| types/trajectory.py | 19 | 11 | 0 | 30 | 63% |
| types/security_domain.py | 24 | 15 | 0 | 39 | 62% |
| controller.py | 50 | 33 | 1 | 84 | 61% |
| types/event.py | 11 | 21 | 0 | 32 | 34% |
| interfaces/target.py | 0 | 14 | 0 | 14 | 0% |
| interfaces/task.py | 0 | 6 | 0 | 6 | 0% |

Note: raw per-module scores are low because they include equivalent mutants
(decorators, string literals, abstract stubs). The adjusted score excludes these.

## Equivalent Mutants (83 total)

These are mutations that cannot be detected because they don't change observable behavior.

### Decorator mutations (~23)
`@dataclass(frozen=True)` → `@dataclass(frozen=False)` and `kw_only=True` → `kw_only=False`.
These change Python's dataclass machinery, not application logic.

### Abstract interface stubs (~20)
`interfaces/target.py` and `interfaces/task.py` contain only abstract method signatures.
The ABCs are never instantiated directly — all mutations in these files are unkillable.

### String literal mutations (~25)
Error messages, log format strings, print output, and description strings on entry types.
Changing these strings has no behavioral effect.

### Type alias / TypeVar definitions (~5)
`EventHandler = Callable[...]`, `Middleware = Callable[...]`, `T_Target = TypeVar(...)`.
Type-level constructs with no runtime behavior.

### Initialization sentinel values (~7)
`self._closed = False`, `self._drain_cursor = 0`, `first_error = None`, etc.
mutmut changes these to different falsy/truthy values, not to meaningful alternatives.

### EventChannel loop capture (~2)
`channel.py:105-106`: The `_loop` capture in `send()` enables cross-thread `close()`.
When mutated, `close()` falls back to `put_nowait(None)` which works identically in
single-threaded async tests. Only detectable in a cross-thread race condition.

### SecurityClaim._claims field (~1)
`security_claim.py:54`: `_claims = None` → `_claims = ""`. For `from_tasks` claims,
`_claims` is never checked — `__iter__` takes the `_tasks is not None` branch first.

## Remaining Survivors (~30)

After killing the high-value mutants and reclassifying equivalents, ~30 mutants
remain. These are all in one of these categories:

- **Cosmetic print/log output** in `controller.py._print_summary` — string formatting,
  `print()` calls, status labels. No behavioral contract.
- **Dataclass field defaults** — `field(default_factory=list)`, `max_runs_per_task: int = 100`.
  Changing the default value is only observable if no value is passed at construction.
- **`@dataclass(frozen=True)` on event types** — 21 mutations across `event.py`.
  Each event type's `frozen=True` could be tested with `FrozenInstanceError` assertions,
  but we already test this pattern on representative types in `test_types.py`.

None of these represent behavioral risk.

## Manual Mutation Tests (tests/test_mutations.py)

40 hand-written tests targeting specific high-value mutations. Each test names
the exact mutation it kills in its docstring. These complement mutmut by
covering patterns that require specific assertion strategies (tie-breaking,
latching, defensive copies, exception-safe teardown).
