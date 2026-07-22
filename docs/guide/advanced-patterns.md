---
layout: doc
title: "Advanced Patterns"
permalink: /guide/advanced-patterns
---

# Advanced Patterns

Patterns you reach for once the basics are in place. Each is independent; read
the ones you need.

## Multi-turn targets

A target can hold a multi-turn conversation. The clean convention (used by the
chatbot target) is to let the **optimizer control how many turns happen**: each
turn the target asks for the next user message; an injection continues the
conversation, a `ControllableNoInjection` ends it.

```python
async def run(self, emit, send_event):
    messages = [{"role": "system", "content": self._system_prompt}]

    for turn in range(self._max_turns):
        resp = await send_event(ControllablePreCallEvent(
            controllable=_USER_MESSAGE_CTRL, request=f"Turn {turn + 1} user message"))

        if not isinstance(resp, ControllableInjection):
            break                        # attacker declined: end the conversation
        user_msg = resp.value
        messages.append({"role": "user", "content": user_msg})
        emit(ObservableEvent(observable=_REQUEST_OBS, content=user_msg))

        completion = await acompletion(model=self._model, messages=messages,
                                       api_base=self._api_base, api_key=self._api_key)
        assert isinstance(completion, ModelResponse)
        assistant = completion.choices[0].message.content or ""
        messages.append({"role": "assistant", "content": assistant})
        self._last_response = assistant
        emit(ObservableEvent(observable=_RESPONSE_OBS, content=assistant))

        # Optional: let the attacker see this turn's reply before the next turn.
        await send_event(ControllablePostCallEvent(
            controllable=_USER_MESSAGE_CTRL, request=f"Turn {turn + 1}", answer=assistant))
```

The attacker sees one `ControllablePreCallEvent` per turn and can adapt each
message from the conversation visible in its filtered trajectory. A `max_turns`
ceiling in the target keeps a run finite even if the attacker keeps injecting.

## Parallel branches inside one run

A target may fan out into concurrent branches, each calling `send_event`
independently. Each call suspends only its own branch and resumes when the
attacker responds.

{% include diagrams/u8.html %}

```python
import asyncio

async def run(self, emit, send_event):
    async def branch(ctrl, label):
        resp = await send_event(ControllablePreCallEvent(controllable=ctrl, request=label))
        value = resp.value if isinstance(resp, ControllableInjection) else "default"
        emit(ObservableEvent(observable=Observable(name=f"{label}_input",
             security_domain=ctrl.security_domain, description=label), content=value))
        return value

    a, b = await asyncio.gather(branch(_SEARCH_CTRL, "search"), branch(_GEN_CTRL, "generate"))
    self._last_response = await self._combine(a, b)
```

The default (sequential) optimizer handles the two events one after another; both
branches resume once answered. The channel is built for exactly this.

## Thread-based targets

If your target drives work on background threads (Docker containers,
subprocesses), bridge back to the event loop with
`asyncio.run_coroutine_threadsafe`. The channel and envelope are thread-safe
(they use `call_soon_threadsafe` internally).

```python
import asyncio

async def run(self, emit, send_event):
    loop = asyncio.get_running_loop()

    def in_thread():
        fut = asyncio.run_coroutine_threadsafe(
            send_event(ControllablePreCallEvent(controllable=_CTRL, request="input")), loop)
        return fut.result(timeout=30)        # blocks this thread, not the loop

    resp = await loop.run_in_executor(None, in_thread)
```

## Composing security claims

Build large evaluation suites from small, independent claims. Composition is
lazy and re-iterable:

```python
prompt_injection = SecurityClaim.from_tasks([SystemPromptLeakTask(), InstructionIgnoreTask()])
data_exfil       = SecurityClaim.from_tasks([SecretExtractionTask(), PIIExfilTask()])

full = SecurityClaim.from_claims([prompt_injection, data_exfil])

# Analyse by task afterwards:
for tr in result.task_results:
    print(f"{tr.task.goal.description}: {'PASS' if tr.success else 'FAIL'}")
```

## Testing several scopes

Run the same claim under different scopes to chart the attack surface. Build a
Controller per scope and drive them through `run_all`, so the whole sweep shares
one live dashboard and one results folder (see [Running
Evaluations](/guide/running-evaluations#sweeping-multiple-threat-models)):

```python
from superred.core.controller import run_all

scopes = {"user": frozenset({USER_TAG}),
          "user+system": frozenset({USER_TAG, SYSTEM_PROMPT_TAG})}

controllers = [
    Controller(optimizer_factory=lambda: MyOptimizer(), target_factory=target_factory,
               security_claim=claim, scope=scope, llm_config=attacker_cfg,
               results_dir="results")
    for scope in scopes.values()
]
results = await run_all(controllers, concurrency=2)   # one shared dashboard; input order
for name, result in zip(scopes, results):
    succ = sum(1 for tr in result.task_results if tr.success)
    print(f"{name}: {succ}/{len(result.task_results)}")
```
