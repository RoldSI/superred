# Target Interface

The AI system under test. Exposes four surfaces:

## Pre-run configuration
- `config_specs -> list[ConfigSpec]` — declares named text-valued config slots with security domains.
- `set_config(name, value)` — accepts a config value before a run.

## Post-run state
- `state_specs -> list[StateSpec]` — declares named queryable state (name + description).
- `get_state(name) -> str` — returns post-run ground truth for evaluation.

Config and state are **intentionally distinct**. What you configure before a run (e.g. seeding a database) is not the same as what you query after (e.g. the model's final response).

## Runtime surfaces
- `get_controllables() -> list[Controllable]` — injection points the optimizer can manipulate during a run.
- `get_observables() -> list[ObservableValue]` — static context about the system.

## Execution
- `run(trajectory, send_event)` — execute one run. Emit entries to trajectory. Call `send_event(event)` at controllable points and use the response.

`EventHandler = Callable[[Event], Awaitable[EventResponse]]` — the `send_event` callback. Can be wired directly to the optimizer or through a controller queue. The target doesn't know or care.

## Design decisions

- **Config vs state separation**: A target may expose completely different specs for pre-run setup and post-run queries. This models the real distinction between "what you seed" and "what you observe after."
- **State is always text**: Both ConfigSpec and StateSpec values are strings. The description documents the format. The target interprets the text (run SQL, parse JSON, execute bash, etc.).
- **`send_event` as callback**: Decouples the target from the optimizer. The same target works with direct optimizer calls or through a controller queue — it just calls `send_event` and gets a response.
