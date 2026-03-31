"""Generic target for any AI system accessible via HTTP API.

Configure via YAML or dataclass.  Supports injection into request bodies.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

import httpx

from superred.core.types.context import ActionRecord, ObservationRecord, TurnResult
from superred.core.types.threat_model import (
    InterfaceRole,
    InterfaceSpec,
    RuntimeParamSpec,
    SecurityDomain,
    TargetMetadata,
    ThreatModel,
)
from superred.core.types.trajectory import EventKind, TraceEvent


@dataclass
class APITargetConfig:
    """YAML-serialisable configuration for an API target."""

    name: str = "api_target"
    base_url: str = ""
    endpoint: str = "/v1/chat/completions"
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    request_template: dict[str, Any] = field(default_factory=dict)
    injection_field: str = ""
    response_field: str = ""
    timeout_seconds: float = 120.0


class APIRunSession:
    """A single run session against an HTTP API target."""

    def __init__(
        self,
        client: httpx.Client,
        config: APITargetConfig,
        threat_model: ThreatModel,
    ):
        self._client = client
        self._config = config
        self._threat_model = threat_model
        self._trace: list[TraceEvent] = []
        self._controllable_values: dict[str, Any] = {}
        self._step_count = 0

    def threat_model(self) -> ThreatModel:
        return self._threat_model

    def available_controllables(self) -> Sequence[InterfaceSpec]:
        specs = [
            InterfaceSpec(
                name="user_message",
                role=InterfaceRole.CONTROLLABLE,
                domains=frozenset({SecurityDomain.USER}),
                description="User message content",
            ),
        ]
        if self._config.injection_field:
            specs.append(InterfaceSpec(
                name="injection_point",
                role=InterfaceRole.CONTROLLABLE,
                domains=frozenset({SecurityDomain.EXTERNAL_DATA}),
                description=f"Injection at {self._config.injection_field}",
            ))
        return [s for s in specs if s.name in self._threat_model.allowed_controllables]

    def available_observables(self) -> Sequence[InterfaceSpec]:
        return [
            InterfaceSpec(
                name="api_response",
                role=InterfaceRole.OBSERVABLE,
                domains=frozenset({SecurityDomain.USER}),
                description="API response body",
            ),
        ]

    def apply_controllables(self, values: Mapping[str, Any]) -> None:
        self._controllable_values.update(values)

    def step(self) -> TurnResult:
        self._step_count += 1
        ts = int(time.time() * 1000)

        request_body = dict(self._config.request_template)
        if "user_message" in self._controllable_values:
            _set_nested(request_body, "messages[-1].content", self._controllable_values["user_message"])
        if "injection_point" in self._controllable_values and self._config.injection_field:
            _set_nested(request_body, self._config.injection_field, self._controllable_values["injection_point"])

        self._trace.append(TraceEvent(
            event_id=f"req-{self._step_count}",
            parent_event_id=None,
            timestamp_ms=ts,
            actor="api_target",
            kind=EventKind.MODEL_REQUEST,
            domains=frozenset({SecurityDomain.MODEL}),
            payload={"request": request_body},
        ))

        response = self._client.request(
            self._config.method,
            self._config.endpoint,
            json=request_body,
        )
        response_data = response.json()

        self._trace.append(TraceEvent(
            event_id=f"resp-{self._step_count}",
            parent_event_id=f"req-{self._step_count}",
            timestamp_ms=int(time.time() * 1000),
            actor="api_target",
            kind=EventKind.MODEL_RESPONSE,
            domains=frozenset({SecurityDomain.MODEL, SecurityDomain.USER}),
            payload={"response": response_data},
        ))

        return TurnResult(
            action=ActionRecord(
                action_id=f"action-{self._step_count}",
                action_type="api_call",
                name="api_request",
                arguments=dict(self._controllable_values),
            ),
            observation=ObservationRecord(
                observation_id=f"obs-{self._step_count}",
                source_ids=(),
                payload=response_data,
            ),
            new_events=list(self._trace[-2:]),
            done=True,
        )

    def trace(self) -> Sequence[TraceEvent]:
        return list(self._trace)

    def close(self) -> None:
        self._controllable_values.clear()


class APITarget:
    """Target wrapping any HTTP API endpoint.

    Conforms to the :class:`TargetModuleInterface` protocol.
    """

    def __init__(self, config: APITargetConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=config.base_url,
            headers=config.headers,
            timeout=config.timeout_seconds,
        )

    # ---- TargetModuleInterface ----

    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            target_id=f"api_{self.config.name}",
            display_name=self.config.name,
            description=f"API target at {self.config.base_url}{self.config.endpoint}",
            version="1.0",
            observability_tier="proxy",
        )

    def controllables(self) -> Sequence[InterfaceSpec]:
        specs = [
            InterfaceSpec(
                name="user_message",
                role=InterfaceRole.CONTROLLABLE,
                domains=frozenset({SecurityDomain.USER}),
                description="User message content",
            ),
        ]
        if self.config.injection_field:
            specs.append(InterfaceSpec(
                name="injection_point",
                role=InterfaceRole.CONTROLLABLE,
                domains=frozenset({SecurityDomain.EXTERNAL_DATA}),
                description=f"Injection at {self.config.injection_field}",
            ))
        return specs

    def observables(self) -> Sequence[InterfaceSpec]:
        return [
            InterfaceSpec(
                name="api_response",
                role=InterfaceRole.OBSERVABLE,
                domains=frozenset({SecurityDomain.USER}),
                description="API response body",
            ),
        ]

    def feedback_channels(self) -> Sequence[InterfaceSpec]:
        return [
            InterfaceSpec(
                name="attack_success",
                role=InterfaceRole.FEEDBACK,
                domains=frozenset({SecurityDomain.VERIFIER}),
                description="Attack success judge",
            ),
        ]

    def runtime_params(self) -> Sequence[RuntimeParamSpec]:
        return []

    def open_run(
        self,
        *,
        threat_model: ThreatModel,
        runtime_params: Mapping[str, Any],
    ) -> APIRunSession:
        return APIRunSession(
            client=self._client,
            config=self.config,
            threat_model=threat_model,
        )


def _set_nested(d: dict[str, Any], path: str, value: Any) -> None:
    """Set a value in a nested dict using dot-separated path."""
    keys = path.split(".")
    for key in keys[:-1]:
        if key.endswith("[-1]"):
            key = key[:-4]
            d = d.setdefault(key, [{}])[-1]
        else:
            d = d.setdefault(key, {})
    d[keys[-1]] = value
