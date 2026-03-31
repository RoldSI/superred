"""Static injection optimizer -- no learning, just injects a fixed string."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from superred.core.types.budget import BudgetEstimate, HierarchicalBudget
from superred.core.types.controllable import ControllableValue
from superred.core.types.feedback import FeedbackResult
from superred.core.types.observable import StaticObservable
from superred.core.types.threat_model import InterfaceSpec
from superred.core.types.trajectory import TraceEvent


@dataclass
class StaticInjection:
    """Injects a fixed adversarial string.  Useful as baseline."""

    injection_text: str
    target_interface: str = "tool_response_injection"

    def initialize(
        self,
        goal: str,
        controllables: list[InterfaceSpec],
        static_observables: list[StaticObservable],
        budget: HierarchicalBudget | None = None,
    ) -> None:
        pass

    def step(
        self,
        trace: Sequence[TraceEvent] | None = None,
        feedback: FeedbackResult | None = None,
    ) -> list[ControllableValue]:
        return [ControllableValue(name=self.target_interface, value=self.injection_text)]

    def is_exhausted(self) -> bool:
        return True

    def receive_feedback(self, feedback: FeedbackResult) -> None:
        pass

    def estimate_budget(self) -> BudgetEstimate:
        return BudgetEstimate(estimated_iterations=1, confidence=1.0)

    def get_sub_optimizers(self) -> list[Any]:
        return []

    def teardown(self) -> None:
        pass

    def get_metadata(self) -> dict[str, Any]:
        return {"type": "static_injection", "injection_length": len(self.injection_text)}

    def get_name(self) -> str:
        return "Static Injection"
