"""LLM client: constrained async LLM access for optimizers.

The controller creates an :class:`LLMClient` from an :class:`LLMConfig`
and passes it to the optimizer. The client locks the model, API base,
and API key — the optimizer can only send messages and receive responses.

Budget enforcement is pre-call: the client checks cumulative cost
against the configured limit before making each LLM call.

Uses litellm internally, so the response is a standard
``litellm.ModelResponse`` (OpenAI ``ChatCompletion`` format).
"""

from __future__ import annotations

import threading
from typing import Any, cast

from litellm import BadRequestError, ModelResponse, acompletion, completion_cost

from superred.core.types.llm import BudgetExhaustedError, LLMConfig, LLMUsage


def _is_temperature_top_p_conflict(exc: Exception) -> bool:
    """True if *exc* is the provider's "temperature and top_p cannot both be
    specified" 400. Anthropic- and Google-backed models enforce this mutual
    exclusion even when reached through an OpenAI-compatible gateway."""
    msg = str(exc).lower()
    return "top_p" in msg and "temperature" in msg and ("both" in msg or "only one" in msg)


class LLMClient:
    """Constrained LLM client for optimizer use.

    The model, API base, and API key are fixed at construction by the
    controller. The optimizer cannot change them.

    Thread-safe: usage tracking is protected by a lock.

    Args:
        config: The LLM configuration (model, credentials, budget limits).
    """

    def __init__(self, config: LLMConfig) -> None:
        self._model = config.model
        self._api_base = config.api_base
        self._api_key = config.api_key
        self._max_cost = config.max_cost
        self._lock = threading.Lock()
        self._calls = 0
        self._cost = 0.0

    @classmethod
    def _make_noop(cls) -> LLMClient:
        """Create a zero-budget client for non-LLM optimizers.

        The client is a real ``LLMClient`` with ``max_cost=0`` so any
        ``complete()`` call immediately raises ``BudgetExhaustedError``.
        """
        return cls(
            LLMConfig(
                model="noop",
                api_base="http://noop",
                api_key="noop",
                max_cost=0,
            )
        )

    async def complete(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> ModelResponse:
        """Send a chat completion request.

        Args:
            messages: OpenAI-format messages list.
            **kwargs: Additional parameters forwarded to litellm
                (e.g. ``temperature``, ``max_tokens``, ``stop``).
                ``model``, ``api_base``, and ``api_key`` cannot be
                overridden. ``drop_params`` defaults to ``True`` (see below)
                but may be overridden by the caller.

        Returns:
            A ``litellm.ModelResponse`` (OpenAI ``ChatCompletion`` format).

        Raises:
            BudgetExhaustedError: If the cost budget has been reached.
        """
        # Strip keys that would escape the locked configuration.
        kwargs.pop("model", None)
        kwargs.pop("api_base", None)
        kwargs.pop("api_key", None)

        # Drop provider-unsupported sampling params instead of raising. An
        # optimizer is general-purpose: it does not know which model it is
        # pointed at, so a paper-faithful attacker that sends OpenAI-style
        # params (e.g. ``top_p``) must not crash when the locked model rejects
        # them. Anthropic Claude on AWS Bedrock, for instance, raises
        # ``UnsupportedParamsError`` on ``top_p``; with ``drop_params`` litellm
        # silently drops it and keeps it where it is supported. Caller may
        # override (pass ``drop_params=False``) to opt into strict behaviour.
        drop_params = kwargs.pop("drop_params", True)

        self._check_budget_pre_call()

        # acompletion handles every provider, including models litellm routes
        # through the Responses API (e.g. OpenAI gpt-5.x on Bedrock Mantle):
        # litellm (>=1.89.0) bridges chat<->responses internally and returns a
        # normal ModelResponse with usage, so we never branch on the model here.
        async def _call(call_kwargs: dict[str, Any]) -> ModelResponse:
            return cast(
                ModelResponse,
                await acompletion(
                    model=self._model,
                    messages=messages,
                    api_base=self._api_base,
                    api_key=self._api_key,
                    drop_params=drop_params,
                    **call_kwargs,
                ),
            )

        try:
            response = await _call(kwargs)
        except Exception as exc:  # noqa: BLE001
            # Some models (Anthropic / Google-backed) reject temperature AND top_p
            # together. drop_params can't fix a mutual-exclusion constraint (both are
            # individually valid for the provider). The OpenAI-compat gateway reports it
            # explicitly ("cannot both be specified"); the native Anthropic passthrough
            # returns only a generic 400. So when BOTH params were sent, retry once
            # dropping top_p -- on the explicit conflict message OR any BadRequestError.
            # Safe: models that accept both never reach this path (no error), and if a
            # 400 had a different cause the retry fails again and that error surfaces.
            both = "temperature" in kwargs and "top_p" in kwargs
            if both and (_is_temperature_top_p_conflict(exc) or isinstance(exc, BadRequestError)):
                retry_kwargs = {k: v for k, v in kwargs.items() if k != "top_p"}
                response = await _call(retry_kwargs)
            else:
                raise

        self._record_usage(response)
        return response

    @property
    def usage(self) -> LLMUsage:
        """Current cumulative usage."""
        with self._lock:
            return LLMUsage(
                calls=self._calls,
                cost=self._cost,
            )

    def _check_budget_pre_call(self) -> None:
        """Raise BudgetExhaustedError if the cost limit has been reached."""
        if self._max_cost is None:
            return
        with self._lock:
            current = LLMUsage(
                calls=self._calls,
                cost=self._cost,
            )
        if current.cost >= self._max_cost:
            raise BudgetExhaustedError(
                f"Cost limit reached: ${current.cost:.6f}/${self._max_cost:.6f}",
                usage=current,
            )

    def _record_usage(self, response: ModelResponse) -> None:
        """Update cumulative usage from a response.

        Raises:
            RuntimeError: If the response does not include usage data.
                Usage tracking is essential for budget enforcement.
        """
        # usage is a dynamic extra field on litellm's ModelResponse (Pydantic extra="allow")
        usage = getattr(response, "usage", None)
        if usage is None:
            raise RuntimeError(
                f"LLM response missing usage data (model={self._model}). "
                "Budget tracking requires usage reporting from the provider."
            )
        call_cost = completion_cost(completion_response=response)

        # Lock: optimizers may issue concurrent LLM calls (parallel
        # consumption model), so _calls/_cost must be updated atomically.
        with self._lock:
            self._calls += 1
            self._cost += call_cost
