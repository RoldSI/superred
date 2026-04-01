from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetConfig:
    name: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class OptimizerConfig:
    name: str
    params: dict[str, Any] = field(default_factory=dict)
    children: list[OptimizerConfig] = field(default_factory=list)


@dataclass
class TaskConfig:
    name: str
    claims: list[str] = field(default_factory=list)


@dataclass
class ThreatModelConfig:
    sweep: bool = False
    budget: dict[str, Any] = field(default_factory=dict)
    explicit: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class OutputConfig:
    dir: str = "results"
    format: str = "json"


@dataclass
class EvalConfig:
    target: TargetConfig
    optimizer: OptimizerConfig
    task: TaskConfig
    threat_models: ThreatModelConfig = field(default_factory=ThreatModelConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


def load_config(path: str) -> EvalConfig:
    """Load evaluation config from YAML file."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    target = TargetConfig(**raw.get("target", {}))

    opt_raw = raw.get("optimizer", {})
    children = [OptimizerConfig(**c) for c in opt_raw.pop("children", [])] if "children" in opt_raw else []
    # Handle nested children (removed from params)
    opt_params = opt_raw.get("params", {})
    child_configs: list[OptimizerConfig] = []
    if isinstance(opt_params, dict) and "children" in opt_params:
        for c in opt_params.pop("children"):
            child_configs.append(
                OptimizerConfig(
                    name=c["name"],
                    params=c.get("params", {}),
                )
            )
    optimizer = OptimizerConfig(
        name=opt_raw.get("name", ""),
        params=opt_params if isinstance(opt_params, dict) else {},
        children=child_configs or children,
    )

    task = TaskConfig(**raw.get("task", {}))

    tm_raw = raw.get("threat_models", {})
    threat_models = ThreatModelConfig(
        sweep=tm_raw.get("sweep", False),
        budget=tm_raw.get("budget", {}),
        explicit=tm_raw.get("explicit", []),
    )

    out_raw = raw.get("output", {})
    output = OutputConfig(**out_raw)

    return EvalConfig(
        target=target,
        optimizer=optimizer,
        task=task,
        threat_models=threat_models,
        output=output,
    )
