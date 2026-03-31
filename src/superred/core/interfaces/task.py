"""Task module interface and security claim protocols.

A task module carries the security specification for a given evaluation: the
goal, the evaluator / judge, the feedback signal, and the security claims.
It is fully separate from the target module — it is only configured with one
at runtime via ``bind(target)`` and then becomes the controller-facing
interface for that evaluation.

Security claims are modelled as target-agnostic predicates over normalised
execution context, action and observation records, and an oracle bundle.
The four first-class claim families come directly from the contextual agent
security framework.

Plugin authors implement classes conforming to :class:`TaskModuleInterface`,
:class:`BoundTaskTargetInterface`, :class:`EvaluatedRunInterface`,
:class:`SecurityClaim`, and :class:`OracleBundle`.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Protocol, Sequence, runtime_checkable

from superred.core.interfaces.target import TargetModuleInterface
from superred.core.types.context import (
    ActionRecord,
    ContextSnapshot,
    ObservationRecord,
    TurnResult,
)
from superred.core.types.security_claims import ClaimVerdict, OracleEvidence
from superred.core.types.task import TaskDefinition, TaskFeedback
from superred.core.types.threat_model import (
    InterfaceSpec,
    PropertyKind,
    TargetMetadata,
    ThreatModel,
)
from superred.core.types.trajectory import TraceEvent


# ------------------------------------------------------------------
# Oracle and claim protocols
# ------------------------------------------------------------------


@runtime_checkable
class OracleBundle(Protocol):
    """Bundle of oracle functions used to evaluate security claims.

    Oracles recover instruction attribution, source attribution, and
    objective alignment from normalised execution artefacts.  They are
    target-independent by construction.
    """

    def instruction_attribution(
        self,
        *,
        context: ContextSnapshot,
        action: ActionRecord,
    ) -> OracleEvidence: ...

    def source_attribution(
        self,
        *,
        observation: ObservationRecord,
    ) -> OracleEvidence: ...

    def prompt_objective(
        self,
        *,
        user_prompt: str,
    ) -> OracleEvidence: ...

    def trajectory_objective(
        self,
        *,
        trajectory: Sequence[tuple[ActionRecord, ObservationRecord]],
    ) -> OracleEvidence: ...

    def action_objective_alignment(
        self,
        *,
        context: ContextSnapshot,
        action: ActionRecord,
    ) -> OracleEvidence: ...


@runtime_checkable
class SecurityClaim(Protocol):
    """A target-agnostic security predicate.

    Claims evaluate a normalised context snapshot plus action / observation
    records through a bundle of target-independent oracle interfaces.
    """

    claim_id: str
    property_kind: PropertyKind
    description: str

    def required_oracles(self) -> frozenset[str]: ...

    def required_interfaces(self) -> frozenset[str]: ...

    def evaluate(
        self,
        *,
        context: ContextSnapshot,
        action: ActionRecord,
        observation: Optional[ObservationRecord],
        oracles: OracleBundle,
    ) -> ClaimVerdict: ...


# ------------------------------------------------------------------
# Evaluated run interface
# ------------------------------------------------------------------


@runtime_checkable
class EvaluatedRunInterface(Protocol):
    """Session interface for a single evaluation run, including task feedback.

    Like :class:`TargetRunInterface` but adds ``latest_feedback()`` so that
    the controller can read evaluator output without collapsing it into
    target-generated observables.
    """

    def threat_model(self) -> ThreatModel: ...

    def available_controllables(self) -> Sequence[InterfaceSpec]: ...

    def available_observables(self) -> Sequence[InterfaceSpec]: ...

    def apply_controllables(self, values: Mapping[str, Any]) -> None: ...

    def step(self) -> TurnResult: ...

    def latest_feedback(self) -> Optional[TaskFeedback]: ...

    def trace(self) -> Sequence[TraceEvent]: ...

    def close(self) -> None: ...


# ------------------------------------------------------------------
# Bound task-target composite
# ------------------------------------------------------------------


@runtime_checkable
class BoundTaskTargetInterface(Protocol):
    """Controller-facing view after a task module has bound to a target.

    After ``task.bind(target)``, the task module becomes the
    controller-facing interface for that evaluation.  This preserves
    portability across targets while allowing target-specific adaptation
    only in the binding step.
    """

    def metadata(self) -> TargetMetadata: ...

    def task_definition(self) -> TaskDefinition: ...

    def claims(self) -> Sequence[SecurityClaim]: ...

    def open_run(
        self,
        *,
        threat_model: ThreatModel,
        runtime_params: Mapping[str, Any],
    ) -> EvaluatedRunInterface: ...


# ------------------------------------------------------------------
# Task module interface
# ------------------------------------------------------------------


@runtime_checkable
class TaskModuleInterface(Protocol):
    """Top-level task module that is separate from any target.

    A task module defines the evaluation objective, verifier logic, and
    security claims independently of any specific target.  At runtime it
    binds to a target module and becomes the controller-facing interface
    for that evaluation.
    """

    def task_definition(self) -> TaskDefinition: ...

    def claims(self) -> Sequence[SecurityClaim]: ...

    def bind(self, target: TargetModuleInterface) -> BoundTaskTargetInterface: ...
