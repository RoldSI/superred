# Testing

## Philosophy

**Meaningful tests over metrics.** Coverage and mutation scores are diagnostic tools,
not goals. Every test must verify a real behavioral contract — something that would
fail if the implementation were deleted or broken. If a test cannot be explained in
one sentence ("This test verifies that..."), it should not exist.

### Quality rules

- Every test has at least one assertion that would fail if the function under test
  were removed entirely. `pytest.raises` counts as an assertion.
- No mocking of the system under test — only stub external dependencies.
- No shared mutable state between tests — each test is independent.
- Maximum 30 lines per test function body — extract setup into conftest fixtures.
- Descriptive test names: `test_drain_returns_new_entries_only`, not `test_drain_2`.
- Use `@pytest.mark.parametrize` over nearly identical tests.

### Coverage targets

- Line coverage: 95%+ (enforced by `fail_under` in pyproject.toml)
- Branch coverage: 90%+
- MC/DC: required for compound booleans with 2+ sub-expressions —
  each sub-condition independently shown to affect the outcome.

### Mutation testing target

- Adjusted mutation score: 80%+ (excluding equivalent mutants)
- For every surviving non-equivalent mutant: write a test that kills it
- For equivalent mutants: document in MUTATIONS.md with explanation

### Regression policy

- Every bug fix gets a `@pytest.mark.regression` test with a comment
  referencing the fix. These tests are permanent.

## Prerequisites

- Python 3.11–3.13 (3.14 not supported)
- The shared venv at `/Users/simonsure/research/superred/.venv` (Python 3.13)

```bash
# Activate the venv
source /Users/simonsure/research/superred/.venv/bin/activate

# Install dev dependencies (if not already done)
pip install -e ".[dev]"
```

## Running Tests

```bash
# Full suite with coverage (default — configured in pyproject.toml)
pytest

# Without coverage (faster for development)
pytest --no-cov

# Verbose output
pytest -v

# Parallel execution
pytest -n auto --no-cov

# Single file
pytest tests/test_trajectory.py

# Single test by name
pytest -k "test_drain_returns_new_entries_only"

# Integration tests only
pytest -m integration --no-cov

# Property-based tests only
pytest tests/test_properties.py --no-cov

# Mutation-killing tests only
pytest tests/test_mutations.py --no-cov
```

## Test Structure

```
tests/
  conftest.py                  -- Shared fixtures: domain tags, stub optimizer/target/task
  test_types.py                -- Value types: Goal, Score, EvaluationResult,
                                  Controllable, Observable, ConfigSpec, Event hierarchy, etc.
  test_security_domain.py      -- SecurityDomainTag.includes(), SecurityDomain construction,
                                  immutability, roots, distinct_combinations
  test_security_claim.py       -- SecurityClaim factories, iteration, composition
  test_trajectory.py           -- Trajectory emit/drain/snapshot, close, get_domain, threads,
                                  FilteredTrajectory push-based filtering
  test_channel.py              -- EventChannel/EventEnvelope edge cases, concurrency, threads
  test_optimizer.py            -- Optimizer _dispatch lifecycle, trajectory tracking, exceptions
  test_middleware.py            -- compose(), security_domain_filter()
  test_controller.py           -- Controller: run loop, lifecycle, filtering, parallel, scores,
                                  exception safety, validation, edge cases
  test_distinct_combinations.py -- SecurityDomain.distinct_combinations() exhaustive cases
  test_properties.py           -- Hypothesis property-based tests (SecurityDomainTag, Trajectory)
  test_integration.py          -- End-to-end workflows: full pipeline, security scoping,
                                  multi-task, feedback loop, parallel, post-call events,
                                  past trajectories, per-task config
  test_mutations.py            -- Targeted tests killing specific mutation patterns
```

## Test Categories

| Category | Marker | Count | Purpose |
|----------|--------|-------|---------|
| Unit | (none) | ~155 | Individual module contracts |
| Integration | `@pytest.mark.integration` | 12 | Multi-component workflows |
| Property-based | Hypothesis `@given` | 11 | Invariants over random inputs |
| Mutation-killing | (none, in test_mutations.py) | 40 | Targeted mutation defense |
| Exception safety | (in test_controller.py, test_optimizer.py) | 7 | Error propagation and teardown |

## Current Metrics

- **Tests**: 220
- **Line coverage**: 100% (532/532 statements, 0 missed)
- **Branch coverage**: 99% (86/88 branches, 2 partial)
- **Mutation score (mutmut v2)**: 87.6% adjusted (211/241 non-equivalent), 62.3% raw (202/324 total)
- **Property-based tests**: 11 (Hypothesis, 200 examples each)
- **Thread-safety tests**: 3 (concurrent emit, respond-from-thread, close-from-thread)

### Known gaps (2 partial branches)

| Location | Type | Reason |
|----------|------|--------|
| `optimizer.py:110->106` | Partial branch | `if first_error is None` in error-draining loop — second+ error path. |
| `optimizer.py:183->185` | Partial branch | `if self._current_trajectory is not None` in RunEndEvent exception handler. |

Both are in exception-handling code paths that are extremely unlikely in practice.

## Mutation Testing

Mutation testing uses **mutmut v2.5**. See [MUTATIONS.md](MUTATIONS.md) for detailed results.

```bash
# Run mutation testing (takes ~2 minutes)
mutmut run --no-progress

# View summary (note: `mutmut results` may crash due to pony ORM bug on 3.13;
# query the sqlite cache directly as a workaround — see MUTATIONS.md)
mutmut results

# Inspect a specific surviving mutant
mutmut show <id>

# Results cached in .mutmut-cache (sqlite file, git-ignored)
```

Additionally, `tests/test_mutations.py` contains 40 hand-written tests that target
specific high-value mutations. Each test's docstring names the mutation it kills.

## Source Fixes Made During Testing

The test audit uncovered four bugs that were fixed:

1. **Controller.run() teardown not exception-safe**: Teardown was called after the task loop, not in a `finally` block. If a task raised an unexpected exception, `optimizer.teardown()` and `target.teardown()` were never called. **Fixed**: wrapped in `try/finally`.

2. **Optimizer._dispatch deadlock on on_event exception**: If `on_event()` raised, `envelope.respond()` was never called, causing the sender to hang forever. **Fixed**: `_dispatch` now responds with a fallback `EventResponse` before re-raising.

3. **Optimizer.run() deadlock after on_event exception**: After `_dispatch` re-raised, `run()` exited the channel loop, but the controller kept sending events with no receiver. **Fixed**: `run()` now catches dispatch exceptions, stores the first error, continues draining, and re-raises after the channel closes.

4. **No validation on max_runs_per_task**: `max_runs_per_task=0` would trigger an `assert best_score is not None` crash. **Fixed**: `__init__` now validates `max_runs_per_task >= 1`.

## Regression Tests

Tag regression tests with `@pytest.mark.regression` and include a comment referencing
the commit or issue number:

```python
@pytest.mark.regression
async def test_close_before_loop_capture():
    """Regression for commit abc123: EventChannel.close() hung when called
    before any send/receive had captured the event loop."""
    channel = EventChannel()
    channel.close()
    result = await channel.receive()
    assert result is None
```

No regression tests exist yet (no bug-fix commits in git history prior to this test effort).

## Coverage Configuration

Configured in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
addopts = "--cov=superred.core --cov-branch --cov-report=term-missing --strict-markers"

[tool.coverage.report]
fail_under = 95
```

Abstract methods, `TYPE_CHECKING` blocks, and `...` (ellipsis stubs) are excluded.

## Dev Dependencies

All in `[project.optional-dependencies] dev` in `pyproject.toml`:

| Package | Purpose |
|---------|---------|
| `pytest>=8.0` | Test runner |
| `pytest-asyncio>=0.23` | Async test support (`asyncio_mode = "auto"`) |
| `pytest-cov>=6.0` | Coverage reporting with branch coverage |
| `pytest-xdist>=3.5` | Parallel test execution (`-n auto`) |
| `hypothesis>=6.100` | Property-based testing |
| `mutmut>=2.5,<3` | Mutation testing |
| `mypy>=1.10` | Static type checking (strict mode) |
| `ruff>=0.4` | Linting and formatting |
