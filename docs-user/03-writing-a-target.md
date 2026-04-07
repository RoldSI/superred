# Writing a Target

A target wraps the AI system you want to red-team. This guide walks through building one from scratch.

## Minimal Template

```python
from superred.core.interfaces.target import EventHandler, Target
from superred.core.types.controllable import Controllable, ControllableSpec
from superred.core.types.event import ControllableInjection, ControllablePreCallEvent
from superred.core.types.observable import Observable, ObservableValue
from superred.core.types.security_domain import SecurityDomain, SecurityDomainTag
from superred.core.types.state import ConfigSpec, QuerySpec
from superred.core.types.event import LogEvent
from superred.core.types.trajectory import EmitFn

# Step 1: Define your security domain tree
ROOT = SecurityDomainTag("my_system")
USER = SecurityDomainTag("user", parent=ROOT)
DOMAIN = SecurityDomain([ROOT, USER])


class MyTarget(Target):
    """Describe your AI system here."""

    def __init__(self, api_key: str) -> None:
        # Manual values (API keys, URLs) go in the constructor.
        # NOT through the framework's config system.
        self._api_key = api_key
        self._system_prompt = "default"
        self._last_response = ""

    # --- Config: what the task sets before a run ---

    @property
    def config_specs(self) -> list[ConfigSpec]:
        return [
            ConfigSpec(
                name="system_prompt",
                security_domain=ROOT,
                description="The system prompt. Plain text.",
            ),
        ]

    def set_config(self, name: str, value: str) -> None:
        if name == "system_prompt":
            self._system_prompt = value

    # --- Query: what the evaluator reads after a run ---

    @property
    def query_specs(self) -> list[QuerySpec]:
        return [
            QuerySpec(name="last_response", description="The last LLM response."),
        ]

    def query(self, name: str, **params: str) -> str:
        if name == "last_response":
            return self._last_response
        return ""

    # --- Security domain ---

    @property
    def security_domain(self) -> SecurityDomain:
        return DOMAIN

    # --- Controllables: injection points ---

    def get_controllables(self) -> list[Controllable]:
        return [
            Controllable(spec=ControllableSpec(
                name="user_message",
                security_domain=USER,
                description="The user's chat message.",
            )),
        ]

    # --- Observables: static context ---

    def get_observables(self) -> list[ObservableValue]:
        return []

    # --- The main execution ---

    async def run(
        self, emit: EmitFn, send_event: EventHandler,
    ) -> None:
        # 1. Fire controllable event to get optimizer's injection
        ctrl = Controllable(spec=ControllableSpec(
            name="user_message", security_domain=USER,
        ))
        resp = await send_event(
            ControllablePreCallEvent(controllable=ctrl, request="user message"),
        )

        # 2. Extract the injected value
        if isinstance(resp, ControllableInjection):
            user_message = resp.value
        else:
            user_message = "Hello"  # fallback if not controlled

        # 3. Record what was sent to the model
        emit(LogEvent(
            content=user_message,
            label="model_request",
            security_domain=USER,
        ))

        # 4. Call your AI system
        response = await self._call_llm(user_message)
        self._last_response = response

        # 5. Record the model's response
        emit(LogEvent(
            content=response,
            label="model_response",
            security_domain=ROOT,
        ))

    async def _call_llm(self, message: str) -> str:
        # Your actual LLM/API call here
        return "LLM response"

    async def cleanup(self) -> None:
        # Reset state between runs. Called after each evaluation.
        self._last_response = ""

    async def teardown(self) -> None:
        # Release resources. Called once at the end.
        pass
```

## Key Points

### Constructor: Manual Values Only

API keys, URLs, model names, and other operational values go in the constructor. The framework never touches these.

```python
# Good: constructor gets operational values
target = MyTarget(api_key="sk-...", model="gpt-4o")

# The framework uses config_specs for task-level setup
target.set_config("system_prompt", "You are a helpful assistant.")
```

### Config vs Query

These serve different actors at different times:

| | Config | Query |
|---|---|---|
| **Who uses it** | Task (before run) | Task evaluator (after run) |
| **When** | Before `target.run()` | After `target.run()` |
| **Purpose** | Set up the scenario | Check what happened |
| **Example** | System prompt, DB seed | Last response, logs |

### Controllables: The Attack Surface

A controllable is an injection point. During `run()`, you fire a `ControllablePreCallEvent` and the optimizer responds with what to inject.

```python
# Create a controllable
ctrl = Controllable(spec=ControllableSpec(
    name="user_input",
    security_domain=USER_TAG,
    description="The user's message to the chatbot.",
))

# Fire the event and get the optimizer's response
response = await send_event(
    ControllablePreCallEvent(controllable=ctrl, request="What should the user say?"),
)

# Use the injection
if isinstance(response, ControllableInjection):
    user_input = response.value
else:
    # ControllableNoInjection — controllable is outside the tested scope
    user_input = "default value"
```

The `request` field describes what this controllable point needs. The optimizer sees it and decides what to inject.

### Post-Call Events

You can also send `ControllablePostCallEvent` after applying an injection, so the optimizer can observe the effect:

```python
from superred.core.types.event import ControllablePostCallEvent

# After using the injected value and getting a result:
await send_event(
    ControllablePostCallEvent(
        controllable=ctrl,
        request="What should the user say?",
        answer=llm_response,
    ),
)
```

### Trajectory: Recording What Happened

The trajectory records the run's history. Emit `LogEvent` objects as things happen using the `emit` function:

```python
from superred.core.types.event import LogEvent

emit(LogEvent(
    content="the prompt sent to the LLM",
    label="model_request",
    security_domain=USER_TAG,
))

emit(LogEvent(
    content="the LLM's response",
    label="model_response",
    security_domain=ROOT_TAG,
))
```

Every event needs a `security_domain` (or `None` for events that should always be visible regardless of scope). This controls what the optimizer can see via its filtered trajectory view.

### Custom Log Labels

Use the `label` field on `LogEvent` to categorize different kinds of log entries:

```python
# Log a tool invocation
emit(LogEvent(
    content={"tool": "search", "query": "weather"},
    label="tool_call",
    security_domain=ROOT_TAG,
))

# Log a tool result
emit(LogEvent(
    content="search result text",
    label="tool_result",
    security_domain=ROOT_TAG,
))
```

### Cleanup vs Teardown

- **`cleanup()`** - Called after each run+evaluation cycle. Reset databases, clear caches, etc. so the next run starts fresh.
- **`teardown()`** - Called once at the very end. Close connections, stop containers, etc.

## Complete Real Example: SimpleChatTarget

See [simple_chat_target/target.py](../../superred-modules/targets/simple_chat/src/simple_chat_target/target.py) for a working implementation that calls a real LLM via litellm.

## Multiple Controllables

A target can have multiple injection points at different security domains:

```python
def get_controllables(self) -> list[Controllable]:
    return [
        Controllable(spec=ControllableSpec(
            name="user_query",
            security_domain=USER_TAG,
            description="The user's search query.",
        )),
        Controllable(spec=ControllableSpec(
            name="db_result",
            security_domain=INTERNAL_TAG,
            description="The database lookup result.",
        )),
    ]

async def run(self, emit, send_event):
    # Get user query
    user_resp = await send_event(
        ControllablePreCallEvent(controllable=user_ctrl, request="user query"),
    )
    user_query = user_resp.value if isinstance(user_resp, ControllableInjection) else "default"

    # Get DB result (may be outside scope — optimizer won't control it)
    db_resp = await send_event(
        ControllablePreCallEvent(controllable=db_ctrl, request="DB lookup"),
    )
    if isinstance(db_resp, ControllableInjection):
        db_result = db_resp.value
    else:
        db_result = self._real_db_lookup(user_query)

    # Generate response using both
    response = await self._generate(user_query, db_result)
```

When scoped to `USER_TAG`, the optimizer controls `user_query` but `db_result` gets `ControllableNoInjection` automatically.
