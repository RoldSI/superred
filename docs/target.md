# Target Interface

The AI system under test. Exposes five surfaces:

## Manual setup (user-provided via controller)
- `manual_specs -> list[ManualSpec]` — declares required user-provided values (API keys, credentials).
- `set_manual(values: dict[str, str])` — submits all user values at once. Must include all names from `manual_specs`.

These are not set by tasks — they are provided by the user through the controller before any runs.

## Pre-run configuration (task-set)
- `config_specs -> list[ConfigSpec]` — declares named text-valued config slots with security domains.
- `set_config(name, value)` — accepts a config value before a run.

## Post-run queries (evaluator uses)
- `query_specs -> list[QuerySpec]` — declares available post-run interactions (name, description, optional params).
- `query(name, **params) -> str` — executes a post-run query. May be a simple getter (no params) or a parameterized action.

Manual, config, and query are **intentionally distinct**:
- Manual = user secrets, provided once via controller.
- Config = task-set pre-run state, set per task.
- Query = post-run ground truth, may differ from what was configured.

## Runtime surfaces
- `get_controllables() -> list[Controllable]` — injection points the optimizer can manipulate during a run.
- `get_observables() -> list[ObservableValue]` — static context about the system.

## Execution
- `run(trajectory, send_event)` — execute one run. Emit entries to trajectory. Call `send_event(event)` at controllable points and use the response.
- `teardown()` — release resources when evaluation is done.

`EventHandler = Callable[[Event], Awaitable[EventResponse]]` — the `send_event` callback. Can be wired directly to the optimizer or through a controller queue. The target doesn't know or care.

## Design decisions

- **Three-way separation (manual/config/query)**: Manual is user-provided secrets (API keys). Config is task-set pre-run state. Query is post-run ground truth. Different actors, different lifecycles, different security concerns.
- **Values are always text**: ManualSpec, ConfigSpec, and QuerySpec all use strings. The description documents the format. The target interprets the text.
- **Parameterized queries**: `QuerySpec` has `params: list[QueryParam]`. Simple getters have no params. Actions (e.g. "search the DB for X") declare params with names and descriptions.
- **`send_event` as callback**: Decouples the target from the optimizer. The same target works with direct optimizer calls or through a controller queue.
- **`set_manual` takes all values at once**: Ensures the target gets a complete set of manual values. Validation happens at the target.
