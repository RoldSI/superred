# src/superred/types/budget.py
from __future__ import annotations

import math
from dataclasses import dataclass

from superred.types.security import Budget


@dataclass
class BudgetUsage:
    iterations: int = 0
    model_calls: int = 0
    tokens: int = 0
    wall_seconds: float = 0.0
    cost_usd: float = 0.0


class HierarchicalBudget:
    """Tree-structured budget. Children report usage upward."""

    def __init__(self, budget: Budget, parent: HierarchicalBudget | None = None) -> None:
        self._budget = budget
        self._parent = parent
        self._usage = BudgetUsage()

    @property
    def usage(self) -> BudgetUsage:
        return self._usage

    @property
    def remaining(self) -> Budget:
        def _rem(limit: int | None, used: int) -> int | None:
            return None if limit is None else max(0, limit - used)
        def _rem_f(limit: float | None, used: float) -> float | None:
            return None if limit is None else max(0.0, limit - used)
        return Budget(
            max_iterations=_rem(self._budget.max_iterations, self._usage.iterations),
            max_model_calls=_rem(self._budget.max_model_calls, self._usage.model_calls),
            max_tokens=_rem(self._budget.max_tokens, self._usage.tokens),
            max_wall_seconds=_rem_f(self._budget.max_wall_seconds, self._usage.wall_seconds),
            max_cost_usd=_rem_f(self._budget.max_cost_usd, self._usage.cost_usd),
        )

    @property
    def exhausted(self) -> bool:
        b, u = self._budget, self._usage
        if b.max_iterations is not None and u.iterations >= b.max_iterations:
            return True
        if b.max_model_calls is not None and u.model_calls >= b.max_model_calls:
            return True
        if b.max_tokens is not None and u.tokens >= b.max_tokens:
            return True
        if b.max_wall_seconds is not None and u.wall_seconds >= b.max_wall_seconds:
            return True
        if b.max_cost_usd is not None and u.cost_usd >= b.max_cost_usd:
            return True
        return False

    def record(self, **kwargs: int | float) -> None:
        for key, val in kwargs.items():
            current = getattr(self._usage, key)
            setattr(self._usage, key, current + val)
        if self._parent is not None:
            self._parent.record(**kwargs)

    def allocate(self, fraction: float) -> HierarchicalBudget:
        def _scale_int(v: int | None) -> int | None:
            return None if v is None else max(1, math.floor(v * fraction))
        def _scale_float(v: float | None) -> float | None:
            return None if v is None else v * fraction
        child_budget = Budget(
            max_iterations=_scale_int(self._budget.max_iterations),
            max_model_calls=_scale_int(self._budget.max_model_calls),
            max_tokens=_scale_int(self._budget.max_tokens),
            max_wall_seconds=_scale_float(self._budget.max_wall_seconds),
            max_cost_usd=_scale_float(self._budget.max_cost_usd),
        )
        return HierarchicalBudget(budget=child_budget, parent=self)
