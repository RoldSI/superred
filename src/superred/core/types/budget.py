"""Hierarchical budget entities for optimizer cost control and estimation.

Budget flows top-down: the controller allocates a budget to the top-level
optimizer, which may spawn child budgets for sub-optimizers. A child's budget
cannot exceed its parent's remaining allocation.

Supports two modes:
- **Estimation mode**: Optimizers report static and updated cost estimates that
  propagate up the hierarchy for high-level planning.
- **Budget mode**: Hard limits on consumption; iteration stops when exhausted.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BudgetUsage:
    """Actual resource consumption tracked during execution."""

    input_tokens: int = 0
    output_tokens: int = 0
    iterations: int = 0
    cost_usd: float = 0.0
    wall_clock_seconds: float = 0.0

    def __add__(self, other: BudgetUsage) -> BudgetUsage:
        return BudgetUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            iterations=self.iterations + other.iterations,
            cost_usd=self.cost_usd + other.cost_usd,
            wall_clock_seconds=self.wall_clock_seconds + other.wall_clock_seconds,
        )


@dataclass
class BudgetEstimate:
    """A cost estimate from an optimizer, propagated up the hierarchy."""

    estimated_iterations: int = 0
    estimated_input_tokens_per_iteration: int = 0
    estimated_output_tokens_per_iteration: int = 0
    confidence: float = 0.0

    @classmethod
    def unknown(cls) -> BudgetEstimate:
        """Return an estimate indicating the optimizer cannot predict its cost."""
        return cls(confidence=0.0)

    @property
    def estimated_total_input_tokens(self) -> int:
        return self.estimated_iterations * self.estimated_input_tokens_per_iteration

    @property
    def estimated_total_output_tokens(self) -> int:
        return self.estimated_iterations * self.estimated_output_tokens_per_iteration


@dataclass
class HierarchicalBudget:
    """A hierarchical budget entity that tracks limits and consumption.

    Supports spawning child budgets whose allocations are bounded by the
    parent's remaining capacity.
    """

    max_input_tokens: int = 0
    max_output_tokens: int = 0
    max_iterations: int = 0
    max_cost_usd: float = 0.0
    max_wall_clock_seconds: float = 0.0
    usage: BudgetUsage = field(default_factory=BudgetUsage)
    _children: list[HierarchicalBudget] = field(default_factory=list, repr=False)
    _parent: HierarchicalBudget | None = field(default=None, repr=False)

    @property
    def remaining_input_tokens(self) -> int | None:
        if self.max_input_tokens == 0:
            return None
        return max(0, self.max_input_tokens - self.usage.input_tokens)

    @property
    def remaining_output_tokens(self) -> int | None:
        if self.max_output_tokens == 0:
            return None
        return max(0, self.max_output_tokens - self.usage.output_tokens)

    @property
    def remaining_iterations(self) -> int | None:
        if self.max_iterations == 0:
            return None
        return max(0, self.max_iterations - self.usage.iterations)

    @property
    def is_exhausted(self) -> bool:
        if self.max_input_tokens > 0 and self.usage.input_tokens >= self.max_input_tokens:
            return True
        if self.max_output_tokens > 0 and self.usage.output_tokens >= self.max_output_tokens:
            return True
        if self.max_iterations > 0 and self.usage.iterations >= self.max_iterations:
            return True
        if self.max_cost_usd > 0 and self.usage.cost_usd >= self.max_cost_usd:
            return True
        if (
            self.max_wall_clock_seconds > 0
            and self.usage.wall_clock_seconds >= self.max_wall_clock_seconds
        ):
            return True
        return False

    def spawn_child(
        self,
        max_input_tokens: int = 0,
        max_output_tokens: int = 0,
        max_iterations: int = 0,
        max_cost_usd: float = 0.0,
        max_wall_clock_seconds: float = 0.0,
    ) -> HierarchicalBudget:
        """Create a child budget bounded by this budget's remaining capacity."""
        child = HierarchicalBudget(
            max_input_tokens=self._cap(max_input_tokens, self.remaining_input_tokens),
            max_output_tokens=self._cap(max_output_tokens, self.remaining_output_tokens),
            max_iterations=self._cap(max_iterations, self.remaining_iterations),
            max_cost_usd=self._cap_float(max_cost_usd, self.max_cost_usd - self.usage.cost_usd),
            max_wall_clock_seconds=self._cap_float(
                max_wall_clock_seconds,
                self.max_wall_clock_seconds - self.usage.wall_clock_seconds,
            ),
            _parent=self,
        )
        self._children.append(child)
        return child

    def record_usage(self, usage: BudgetUsage) -> None:
        """Record consumption against this budget and propagate to parent."""
        self.usage = self.usage + usage
        if self._parent is not None:
            self._parent.record_usage(usage)

    @staticmethod
    def _cap(requested: int, remaining: int | None) -> int:
        if remaining is None:
            return requested
        if requested == 0:
            return remaining
        return min(requested, remaining)

    @staticmethod
    def _cap_float(requested: float, remaining: float) -> float:
        if remaining <= 0:
            return requested
        if requested == 0.0:
            return remaining
        return min(requested, remaining)
