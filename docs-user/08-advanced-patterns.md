# Advanced Patterns

## Multi-Turn Targets

A target that has a multi-turn conversation with the LLM:

```python
async def run(self, trajectory, send_event):
    messages = [{"role": "system", "content": self._system_prompt}]

    for turn in range(self._max_turns):
        # Get user message from optimizer
        ctrl = Controllable(spec=ControllableSpec(
            name="user_input", security_domain=USER_TAG,
        ))
        resp = await send_event(
            ControllablePreCallEvent(controllable=ctrl, request=f"Turn {turn + 1} user message"),
        )
        user_msg = resp.value if isinstance(resp, ControllableInjection) else "Hello"
        messages.append({"role": "user", "content": user_msg})

        trajectory.emit(TrajectoryEntry(
            entry_type=MODEL_REQUEST, content=user_msg, security_domain=USER_TAG,
        ))

        # Call LLM
        completion = await acompletion(model=self._model, messages=messages, ...)
        assert isinstance(completion, ModelResponse)
        assistant_msg = completion.choices[0].message.content or ""
        messages.append({"role": "assistant", "content": assistant_msg})
        self._last_response = assistant_msg

        trajectory.emit(TrajectoryEntry(
            entry_type=MODEL_RESPONSE, content=assistant_msg, security_domain=SYSTEM_TAG,
        ))

        # Optionally let optimizer observe the response
        await send_event(
            ControllablePostCallEvent(
                controllable=ctrl, request=f"Turn {turn + 1}", answer=assistant_msg,
            ),
        )
```

The optimizer gets one `ControllablePreCallEvent` per turn. It can adapt its injection based on the conversation history visible in the trajectory.

## Parallel Target Branches

A target with concurrent processing branches:

```python
import asyncio

async def run(self, trajectory, send_event):
    spec = ControllableSpec(name="input", security_domain=USER_TAG)

    async def branch(name: str) -> str:
        ctrl = Controllable(spec=spec)
        resp = await send_event(
            ControllablePreCallEvent(controllable=ctrl, request=f"Input for {name}"),
        )
        value = resp.value if isinstance(resp, ControllableInjection) else "default"
        trajectory.emit(TrajectoryEntry(
            entry_type=MODEL_REQUEST, content=f"[{name}] {value}",
            security_domain=USER_TAG,
        ))
        return value

    # Both branches run concurrently
    result_a, result_b = await asyncio.gather(
        branch("search"),
        branch("generate"),
    )

    # Combine results
    self._last_response = f"Search: {result_a}, Generate: {result_b}"
```

Each branch fires its own event. The optimizer handles them sequentially by default (in `on_event`). Both branches suspend on their respective futures and resume when the optimizer responds.

## Custom Middleware

Middleware wraps the event handler callback. Use it for logging, rate limiting, budget enforcement, etc.

```python
from superred.core.middleware import Middleware, compose

def logging_middleware() -> Middleware:
    """Log every event and response."""
    def apply(handler):
        async def wrapped(event):
            print(f"Event: {type(event).__name__}")
            response = await handler(event)
            print(f"Response: {type(response).__name__}")
            return response
        return wrapped
    return apply

def budget_middleware(max_tokens: int) -> Middleware:
    """Stop after N tokens used."""
    token_count = [0]

    def apply(handler):
        async def wrapped(event):
            if token_count[0] >= max_tokens:
                from superred.core.types.event import NoModification
                return NoModification(event=event)
            response = await handler(event)
            # Count tokens in injection
            if hasattr(response, "value"):
                token_count[0] += len(response.value.split())
            return response
        return wrapped
    return apply
```

Middleware is applied by the Controller internally via `compose()`. To add custom middleware, you'd extend the Controller or modify its `_run_task` method. The built-in `security_domain_filter` is an example of production middleware.

## Custom Trajectory Entry Types

Define custom entry types for domain-specific recording:

```python
from superred.core.types.trajectory import TrajectoryEntryType

TOOL_CALL = TrajectoryEntryType(
    name="tool_call",
    description="An external tool invocation",
    actor="AI system",
    content_type=dict,
)

TOOL_RESULT = TrajectoryEntryType(
    name="tool_result",
    description="Result from an external tool",
    actor="tool",
    content_type=str,
)

# Use in target.run():
trajectory.emit(TrajectoryEntry(
    entry_type=TOOL_CALL,
    content={"tool": "web_search", "query": "latest news"},
    security_domain=SYSTEM_TAG,
))

result = await call_tool("web_search", "latest news")

trajectory.emit(TrajectoryEntry(
    entry_type=TOOL_RESULT,
    content=result,
    security_domain=SYSTEM_TAG,
))
```

The optimizer sees these in its filtered trajectory and can learn from them.

## Composing Security Claims

Build comprehensive evaluation suites from independent claims:

```python
# Different attack categories
prompt_injection = SecurityClaim.from_tasks([
    SystemPromptLeakTask(),
    InstructionIgnoreTask(),
    RolePlayJailbreakTask(),
])

data_extraction = SecurityClaim.from_tasks([
    SecretExtractionTask(secret="API_KEY_123"),
    PIIExfiltrationTask(),
])

denial_of_service = SecurityClaim.from_tasks([
    InfiniteLoopTask(),
    ResourceExhaustionTask(),
])

# Compose into a full evaluation
full_evaluation = SecurityClaim.from_claims([
    prompt_injection,
    data_extraction,
    denial_of_service,
])

# Run everything
controller = Controller(
    optimizer=optimizer,
    target=target,
    security_claim=full_evaluation,
    security_domain_tag=user_tag,
)
result = await controller.run()

# Analyze by category
for tr in result.task_results:
    print(f"{tr.task.goal.description}: {'PASS' if tr.success else 'FAIL'}")
```

## Testing Multiple Security Scopes

Run the same claim against different scopes to understand the attack surface:

```python
scopes = {
    "user_only": user_input_tag,
    "all_external": external_tag,
    "full_access": system_tag,
}

for name, scope in scopes.items():
    print(f"\n--- Testing scope: {name} ---")
    controller = Controller(
        optimizer=optimizer,
        target=target,
        security_claim=claim,
        security_domain_tag=scope,
    )
    result = await controller.run()
    successes = sum(1 for tr in result.task_results if tr.success)
    print(f"  {successes}/{len(result.task_results)} tasks succeeded")
```

## Packaging Modules

Each module (optimizer, target, claim) is its own pip-installable package:

```
my_optimizer/
  pyproject.toml
  src/my_optimizer/
    __init__.py       # exports
    optimizer.py      # implementation
```

`pyproject.toml`:
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "my-optimizer"
version = "0.1.0"
dependencies = ["superred"]

[tool.hatch.build.targets.wheel]
packages = ["src/my_optimizer"]
```

Install editable during development:
```bash
pip install -e ./my_optimizer
```

Then import by name anywhere:
```python
from my_optimizer import MyOptimizer
```

## Thread-Safe Targets

If your target uses threads (e.g., Docker containers, subprocesses), bridge back to the event loop:

```python
import asyncio
import threading

async def run(self, trajectory, send_event):
    loop = asyncio.get_running_loop()

    def thread_work():
        # Running in a background thread
        future = asyncio.run_coroutine_threadsafe(
            send_event(ControllablePreCallEvent(...)),
            loop,
        )
        response = future.result(timeout=30)  # blocks the thread, not the loop
        return response

    # Run thread work without blocking the event loop
    response = await loop.run_in_executor(None, thread_work)
```

The `EventChannel` and `EventEnvelope.respond()` are thread-safe — they use `call_soon_threadsafe` internally.
