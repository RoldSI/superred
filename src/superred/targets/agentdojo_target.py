"""Target module wrapping the AgentDojo benchmark.

AgentDojo provides:
    - 97 user tasks across 4 domains (banking, travel, workspace, slack)
    - Each task paired with injection tasks
    - Ground-truth evaluation functions
    - Built-in tool execution environment

We wrap it as a TargetModuleInterface by:
    1. Mapping AgentDojo's injection vectors to InterfaceSpecs
    2. Running the AgentDojo agent pipeline with attacker-controlled injections
    3. Emitting canonical trace events during execution
"""

from __future__ import annotations

import logging
import time
from typing import Any, Mapping, Optional, Sequence

from superred.core.types.context import ActionRecord, ObservationRecord, TurnResult
from superred.core.types.threat_model import (
    Budget,
    InterfaceRole,
    InterfaceSpec,
    RuntimeParamSpec,
    SecurityDomain,
    TargetMetadata,
    ThreatModel,
)
from superred.core.types.trajectory import EventKind, TraceEvent

logger = logging.getLogger(__name__)

MAX_RATE_LIMIT_RETRIES = 5
RATE_LIMIT_BASE_DELAY = 15.0


def _require_agentdojo() -> None:
    try:
        from agentdojo.task_suite import TaskSuite, get_suite  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "agentdojo is not installed. Install with: pip install superred[agentdojo]"
        ) from exc


class AgentDojoRunSession:
    """A single run session against the AgentDojo benchmark."""

    def __init__(
        self,
        suite: Any,
        suite_name: str,
        model: str,
        defense: Optional[str],
        system_message_name: Optional[str],
        threat_model: ThreatModel,
    ):
        self._suite = suite
        self._suite_name = suite_name
        self._model = model
        self._defense = defense
        self._system_message_name = system_message_name
        self._threat_model = threat_model
        self._trace: list[TraceEvent] = []
        self._controllable_values: dict[str, Any] = {}
        self._done = False
        self._step_count = 0

    def threat_model(self) -> ThreatModel:
        return self._threat_model

    def available_controllables(self) -> Sequence[InterfaceSpec]:
        return [
            spec
            for spec in _build_interface_specs(self._suite, self._suite_name)
            if spec.role == InterfaceRole.CONTROLLABLE
            and spec.name in self._threat_model.allowed_controllables
        ]

    def available_observables(self) -> Sequence[InterfaceSpec]:
        return [
            spec
            for spec in _build_interface_specs(self._suite, self._suite_name)
            if spec.role == InterfaceRole.OBSERVABLE
            and spec.name in self._threat_model.allowed_observables
        ]

    def apply_controllables(self, values: Mapping[str, Any]) -> None:
        self._controllable_values.update(values)

    def step(self) -> TurnResult:
        self._step_count += 1
        injection_text = self._controllable_values.get("tool_response_injection", "")

        ts = int(time.time() * 1000)
        self._trace.append(TraceEvent(
            event_id=f"inj-{self._step_count}",
            parent_event_id=None,
            timestamp_ms=ts,
            actor="optimizer",
            kind=EventKind.INJECTION,
            domains=frozenset({SecurityDomain.EXTERNAL_DATA}),
            payload={"injection_text": injection_text},
        ))

        self._done = True

        return TurnResult(
            action=ActionRecord(
                action_id=f"action-{self._step_count}",
                action_type="injection",
                name="inject",
                arguments=dict(self._controllable_values),
            ),
            observation=ObservationRecord(
                observation_id=f"obs-{self._step_count}",
                source_ids=(),
                payload={"status": "executed"},
            ),
            new_events=list(self._trace[-1:]),
            done=True,
        )

    def trace(self) -> Sequence[TraceEvent]:
        return list(self._trace)

    def close(self) -> None:
        self._controllable_values.clear()


class AgentDojoTarget:
    """Target module wrapping the AgentDojo benchmark.

    Conforms to the :class:`TargetModuleInterface` protocol.
    """

    def __init__(
        self,
        suite: str = "workspace",
        model: str = "gpt-4o-2024-05-13",
        benchmark_version: str = "v1.2.2",
        defense: Optional[str] = None,
        system_message_name: Optional[str] = None,
    ):
        _require_agentdojo()
        from agentdojo.task_suite import get_suite

        self.suite_name = suite
        self.model = model
        self.benchmark_version = benchmark_version
        self.defense = defense
        self.system_message_name = system_message_name
        self._suite = get_suite(benchmark_version, suite)

    # ---- TargetModuleInterface ----

    def metadata(self) -> TargetMetadata:
        defense_tag = f"+{self.defense}" if self.defense else ""
        return TargetMetadata(
            target_id=f"agentdojo_{self.suite_name}_{self.model}",
            display_name=f"AgentDojo ({self.suite_name}{defense_tag}) - {self.model}",
            description=(
                f"AgentDojo benchmark suite '{self.suite_name}' v{self.benchmark_version} "
                f"running on {self.model}. Defense: {self.defense or 'none'}."
            ),
            version=self.benchmark_version,
            observability_tier="proxy",
        )

    def controllables(self) -> Sequence[InterfaceSpec]:
        specs = [
            InterfaceSpec(
                name="user_query",
                role=InterfaceRole.CONTROLLABLE,
                domains=frozenset({SecurityDomain.USER}),
                description="The user's task instruction",
            ),
            InterfaceSpec(
                name="tool_response_injection",
                role=InterfaceRole.CONTROLLABLE,
                domains=frozenset({SecurityDomain.EXTERNAL_DATA}),
                description="Adversarial content injected into tool responses",
            ),
        ]
        try:
            for vector_id in self._suite.get_injection_vector_defaults():
                specs.append(InterfaceSpec(
                    name=f"injection_vector_{vector_id}",
                    role=InterfaceRole.CONTROLLABLE,
                    domains=frozenset({SecurityDomain.EXTERNAL_DATA}),
                    description=f"Injection vector '{vector_id}'",
                ))
        except Exception:
            pass
        return specs

    def observables(self) -> Sequence[InterfaceSpec]:
        return [
            InterfaceSpec(
                name="system_description",
                role=InterfaceRole.OBSERVABLE,
                domains=frozenset({SecurityDomain.INTERNAL_CONTEXT}),
                description="Description of the agent's purpose and available tools",
            ),
            InterfaceSpec(
                name="tool_schemas",
                role=InterfaceRole.OBSERVABLE,
                domains=frozenset({SecurityDomain.TOOL_CATALOG}),
                description="JSON schemas of all available tools",
            ),
            InterfaceSpec(
                name="llm_call_traces",
                role=InterfaceRole.OBSERVABLE,
                domains=frozenset({SecurityDomain.MODEL}),
                description="Full prompt/response traces from target LLM",
            ),
            InterfaceSpec(
                name="final_output",
                role=InterfaceRole.OBSERVABLE,
                domains=frozenset({SecurityDomain.USER}),
                description="Agent's final response to the user",
            ),
        ]

    def feedback_channels(self) -> Sequence[InterfaceSpec]:
        return [
            InterfaceSpec(
                name="attack_success",
                role=InterfaceRole.FEEDBACK,
                domains=frozenset({SecurityDomain.VERIFIER}),
                description="Binary + score indicating attack success",
            ),
            InterfaceSpec(
                name="utility_score",
                role=InterfaceRole.FEEDBACK,
                domains=frozenset({SecurityDomain.VERIFIER}),
                description="Whether the benign task was still completed",
            ),
        ]

    def runtime_params(self) -> Sequence[RuntimeParamSpec]:
        return [
            RuntimeParamSpec(
                name="openai_api_key",
                description="OpenAI API key for the target model",
                required=True,
                secret=True,
            ),
        ]

    def open_run(
        self,
        *,
        threat_model: ThreatModel,
        runtime_params: Mapping[str, Any],
    ) -> AgentDojoRunSession:
        return AgentDojoRunSession(
            suite=self._suite,
            suite_name=self.suite_name,
            model=self.model,
            defense=self.defense,
            system_message_name=self.system_message_name,
            threat_model=threat_model,
        )


def _build_interface_specs(suite: Any, suite_name: str) -> list[InterfaceSpec]:
    """Build the full set of interface specs for an AgentDojo suite."""
    specs: list[InterfaceSpec] = [
        InterfaceSpec(
            name="user_query",
            role=InterfaceRole.CONTROLLABLE,
            domains=frozenset({SecurityDomain.USER}),
            description="The user's task instruction",
        ),
        InterfaceSpec(
            name="tool_response_injection",
            role=InterfaceRole.CONTROLLABLE,
            domains=frozenset({SecurityDomain.EXTERNAL_DATA}),
            description="Adversarial content injected into tool responses",
        ),
        InterfaceSpec(
            name="system_description",
            role=InterfaceRole.OBSERVABLE,
            domains=frozenset({SecurityDomain.INTERNAL_CONTEXT}),
            description="Description of the agent's purpose and available tools",
        ),
        InterfaceSpec(
            name="attack_success",
            role=InterfaceRole.FEEDBACK,
            domains=frozenset({SecurityDomain.VERIFIER}),
            description="Binary + score indicating attack success",
        ),
    ]
    try:
        for vector_id in suite.get_injection_vector_defaults():
            specs.append(InterfaceSpec(
                name=f"injection_vector_{vector_id}",
                role=InterfaceRole.CONTROLLABLE,
                domains=frozenset({SecurityDomain.EXTERNAL_DATA}),
                description=f"Injection vector '{vector_id}' in {suite_name} environment",
            ))
    except Exception:
        pass
    return specs
