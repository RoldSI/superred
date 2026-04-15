"""LLM access types for the optimizer.

These types define the threat model for optimizer LLM access:
what model is available, what budget the attacker has, and
cumulative usage tracking.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LLMConfig:
    """LLM access configuration for the optimizer.

    Part of the threat model: defines what model the attacker can use
    and what budget they have. Passed to the Controller at construction.

    Attributes:
        model: LiteLLM model identifier (e.g. ``"gpt-4o-mini"``).
        api_base: LiteLLM-compatible API base URL.
        api_key: API key for the LLM provider.
        max_cost: Maximum total cost in USD. ``None`` for unlimited.
            Cost is computed per call via ``litellm.completion_cost()``.
    """

    model: str
    api_base: str
    api_key: str
    max_cost: float | None = None

    def __repr__(self) -> str:
        """Mask api_key in repr to avoid leaking secrets."""
        masked = self.api_key[:4] + "..." if len(self.api_key) > 4 else "***"
        return (
            f"LLMConfig(model={self.model!r}, api_base={self.api_base!r}, "
            f"api_key={masked!r}, max_cost={self.max_cost!r})"
        )


@dataclass(frozen=True)
class LLMUsage:
    """Cumulative LLM usage snapshot.

    Attributes:
        calls: Number of LLM calls made.
        cost: Total cost in USD, computed via ``litellm.completion_cost()``.
    """

    calls: int = 0
    cost: float = 0.0


class BudgetExhaustedError(Exception):
    """Raised when the optimizer exceeds its LLM budget.

    Attributes:
        usage: The cumulative usage at the time the budget was exhausted.
    """

    def __init__(self, message: str, usage: LLMUsage) -> None:
        super().__init__(message)
        self.usage = usage
