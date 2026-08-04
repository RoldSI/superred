---
layout: doc
title: "Models"
permalink: /guide/models
---

# Models

**A model is a configuration value, not code.** Every LLM superred talks to is
named by a string in a config object, so pointing an experiment at a model that
was released this morning is a one-line change. No new module, no subclass, no
framework release, and no change to the attack you are running.

This page covers the three places a model name appears, how to write one, what
to do when a model is so new that nothing knows its price yet, and how to
compare several models in one sweep.

## An experiment has three models

Up to three LLMs take part in an evaluation, and each is configured on its own:

| Role | What it does | Where you set it |
|------|--------------|------------------|
| **Attacker** | writes and refines the attacks | the Controller, as part of the threat model: `Controller(llm_config=...)` |
| **Target** | the system under test | the target's constructor: `ChatbotTarget(model=...)` |
| **Judge** | decides whether an attack succeeded, where the claim uses one | the claim's constructor: `sorry_bench_claim(judge_llm_config=...)` |

The judge is the optional one. A claim whose success condition is checkable
against ground truth, such as whether a planted secret appears in the response or
whether the agent wrote to a file it was not allowed to touch, decides that
deterministically and needs no model at all. A model is only involved when the
question is a matter of judgement, such as whether a response is genuinely
harmful or merely a refusal dressed up as compliance.

They stay separate on purpose. The attacker's model is part of the threat model
(how capable is the adversary?), the target's model is the thing being measured,
and the judge is measurement apparatus that should hold still while the other
two vary. Only the attacker's spend counts against the attacker's budget. See
[the judge is out-of-band](/guide/writing-tasks#the-judge-is-out-of-band-never-the-attackers-llm)
for why the attacker must never share the judge's client.

The rest of this page is about the attacker's model, since that is the one the
`Controller` owns. Targets and claims take a model the same way, as a plain
constructor argument.

## Giving the attacker a model

`LLMConfig` is the whole of it: what to call, where to reach it, how to
authenticate.

```python
import os

from superred.core.controller import Controller
from superred.core.types.llm import LLMConfig

controller = Controller(
    ...,
    llm_config=LLMConfig(
        model="gpt-4o-mini",                     # a LiteLLM model id
        api_base=os.environ["LITELLM_API_BASE"], # where it is served
        api_key=os.environ["LITELLM_API_KEY"],   # the credential
    ),
    task_cost_cap_usd=5.00,                  # the attacker's per-task budget
)
```

Three fields and nothing else. `LLMConfig` is pure access, so the budget is not
part of it: the attacker's cap is `Controller.task_cost_cap_usd`, because two
attack strategies are only comparable when they are given the same money, not
merely the same model. Printing an `LLMConfig` masks the key, and the persisted
results record the model but never the key or the base URL.

Omit `llm_config` for an attacker that needs no model at all, such as a fixed
prompt list or a static encoding trick. The optimizer then receives a noop
client that raises `BudgetExhaustedError` on any call, so a non-LLM attacker
still satisfies the same interface and simply never calls it. Results record
its model as `no-llm`.

## Writing a model identifier

`model` is a [LiteLLM](https://docs.litellm.ai/docs/providers) model
identifier. superred routes every completion through LiteLLM, so any provider
LiteLLM supports is a provider superred supports. The usual form is
`provider/model`:

```python
LLMConfig(model="gpt-4o-mini", ...)              # OpenAI, prefix optional
LLMConfig(model="claude-sonnet-4-5", ...)        # Anthropic
LLMConfig(model="gemini/gemini-2.5-pro", ...)    # Google AI Studio
LLMConfig(model="bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0", ...)
LLMConfig(model="together_ai/deepseek-ai/DeepSeek-V3", ...)
LLMConfig(model="openrouter/openai/gpt-4o", ...) # via a router
LLMConfig(model="ollama/llama3", ...)            # a local model
```

The prefix may be dropped when the name is unambiguous, which is why
`"gpt-4o-mini"` works on its own.

**Behind a gateway.** If your models are served by a proxy (a LiteLLM proxy, an
internal gateway, vLLM), point `api_base` at the gateway and use the name the
gateway registered, prefixed with the API dialect it speaks:

```python
LLMConfig(
    model="openai/my-internal-alias",
    api_base="https://llm.internal.example/v1",
    api_key=os.environ["GATEWAY_KEY"],
)
```

The endpoint has to satisfy exactly two conditions: it speaks an
OpenAI-compatible chat completions API, and it returns a usage block. superred rejects
a response with no usage (`RuntimeError`), because cost tracking, and therefore
the budget cap, is computed from it.

## Using it from an optimizer

The optimizer never picks the model. It receives an `LLMClient` with the model,
base URL, and key already locked, and calls it:

```python
response = await self.llm.complete(
    [{"role": "user", "content": "Rewrite this to evade the filter: ..."}],
)
text = response.choices[0].message.content
```

Three properties of that client are what make a model swap free:

- **The configuration cannot be escaped.** `model`, `api_base`, and `api_key`
  are stripped from the keyword arguments, so no optimizer can quietly call a
  different model than the one the experiment declared.
- **Unsupported sampling parameters are dropped, not fatal.** An attack that
  faithfully reproduces a 2023 paper may send `top_p` to a model that rejects
  it. superred asks LiteLLM to drop such parameters instead of raising, so the
  call proceeds. This is what lets an old attack module run unchanged against a
  new model.
- **The response shape is constant.** Every provider comes back as an
  OpenAI-style `ModelResponse`, so optimizer code that reads
  `response.choices[0].message.content` keeps working across providers.

The full client contract, including `usage` and budget exhaustion, is in
[Writing an Optimizer](/guide/writing-an-optimizer#using-the-llm) and the
[Core Types reference](/reference/types).

## When a new model comes out

Change the string:

```python
llm_config=LLMConfig(model="the-model-released-today", api_base=b, api_key=k)
```

That is the entire change. Nothing downstream needs to be told:

- **The attacker does not need editing**, for the three reasons above.
- **The results stay separate.** The model is part of the experiment identity
  and of the experiment folder name, so a new model lands in its own folder
  rather than mixing with the old numbers, and a re-run of the old model still
  resumes its own results.
- **The dashboard shows it.** Each threat model's live row carries its model, so
  a sweep across models is readable while it runs.

### If the model is too new to be priced

superred enforces the attacker's budget in dollars and computes the cost of each
call with `litellm.completion_cost()`. If the installed LiteLLM release does not
yet know the model, that call raises and the task ends with an error:

```
This model isn't mapped yet. model=openai/brand-new-model,
custom_llm_provider=openai
```

Register a price once, before building the Controller:

```python
import litellm

litellm.register_model({
    "openai/brand-new-model": {
        "input_cost_per_token": 1.0e-6,
        "output_cost_per_token": 2.0e-6,
        "litellm_provider": "openai",
        "mode": "chat",
    }
})
```

Costs are computed from then on and the budget cap behaves normally. Two things
to know about that entry:

- **A guessed price gives you a guessed budget.** The cap is enforced against
  whatever numbers you register, so a placeholder rate keeps the run alive but
  makes `task_cost_cap_usd` mean something other than dollars. Put in the real
  published rate before a cost-sensitive run.
- **Remove it once LiteLLM catches up.** A registered entry overrides the
  built-in map, so a stale entry outlives the problem it solved. Upgrading
  LiteLLM is the permanent fix.

## Comparing models

Because the model is a parameter, comparing models is a loop over Controllers,
one per model, run together:

```python
from superred.core.controller import Controller, run_all

MODELS = ["gpt-4o-mini", "gpt-4o", "claude-sonnet-4-5"]

controllers = [
    Controller(
        ...,
        llm_config=LLMConfig(model=m, api_base=base, api_key=key),
        attacker_label=f"pair-{m}",  # keeps folders and dashboard readable
        results_dir="results",       # one root, a subfolder per model
    )
    for m in MODELS
]

results = await run_all(controllers, concurrency=3)   # results in input order
```

The same shape sweeps the attacker's model against scopes, budgets, or feedback
settings at the same time: build the list of cells you care about and hand it to
`run_all`. See
[Sweeping multiple threat models](/guide/running-evaluations#sweeping-multiple-threat-models)
for the full picture, including what the shared dashboard looks like.

Two cautions when the comparison is the point:

- **Equal budget, not equal calls.** A stronger model costs more per call, so at
  a fixed `task_cost_cap_usd` it gets fewer attempts. That is usually the honest
  comparison (what does a fixed adversary budget buy?), but it is a choice, so
  state it when reporting the numbers.
- **Hold the judge fixed.** Changing the attacker's model and the judge's model
  in the same sweep leaves you unable to say which one moved the result.
