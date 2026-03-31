"""CLI entry point.

Usage:
    superred run --config config.yaml
    superred sweep --config config.yaml
    superred compare --results results1.json results2.json
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import click

from superred.utils.config import load_config


@click.group()
@click.option("--verbose/--quiet", default=True)
def cli(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s [%(name)s] %(message)s",
    )


@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), required=True)
def run(config: str) -> None:
    """Run evaluation from a YAML config file."""
    from superred.controller import Controller
    from superred.core.types.threat_model import Budget
    from superred.metrics import compute_metrics

    cfg = load_config(config)

    target = _build_target(cfg["target"])
    optimizer = _build_optimizer(cfg["optimizer"])
    task = _build_task(cfg.get("task", {}), target)
    controller = Controller()

    threat_models = _build_threat_models(cfg.get("threat_models", []), target)
    budget = Budget(**cfg.get("budget", {}))

    result = controller.run(
        target=target,
        task=task,
        optimizer=optimizer,
        threat_models=threat_models,
        budget=budget,
    )

    metrics = compute_metrics(result)
    click.echo("\n=== RESULTS ===")
    click.echo(json.dumps(result.summary(), indent=2, default=str))

    output_path = cfg.get("output", "results.json")
    with open(output_path, "w") as f:
        json.dump(
            {"config": cfg, "summary": result.summary()},
            f,
            indent=2,
            default=str,
        )
    click.echo(f"\nSaved to {output_path}")


@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), required=True)
def sweep(config: str) -> None:
    """Run evaluation across ALL threat model profiles."""
    from superred.controller import Controller
    from superred.core.types.threat_model import Budget
    from superred.metrics import compute_metrics, format_results_table

    cfg = load_config(config)

    target = _build_target(cfg["target"])
    optimizer = _build_optimizer(cfg["optimizer"])
    task = _build_task(cfg.get("task", {}), target)
    controller = Controller()

    threat_models = _build_threat_models(cfg.get("threat_models", []), target)
    budget = Budget(**cfg.get("budget", {}))

    result = controller.run(
        target=target,
        task=task,
        optimizer=optimizer,
        threat_models=threat_models,
        budget=budget,
    )

    metrics = compute_metrics(result)
    click.echo("\n=== SWEEP RESULTS ===")
    click.echo(format_results_table({optimizer.get_name(): metrics}))

    output_path = cfg.get("output", "results.json")
    with open(output_path, "w") as f:
        json.dump(
            {"config": cfg, "summary": result.summary()},
            f,
            indent=2,
            default=str,
        )
    click.echo(f"\nSaved to {output_path}")


@cli.command()
@click.option(
    "--results", "-r", type=click.Path(exists=True), multiple=True, required=True
)
def compare(results: tuple[str, ...]) -> None:
    """Compare multiple result files side-by-side."""
    all_summaries: dict[str, dict[str, Any]] = {}

    for path in results:
        with open(path) as f:
            data = json.load(f)
        name = Path(path).stem
        all_summaries[name] = data.get("summary", {})

    click.echo("\n=== COMPARISON ===")
    for name, summary in all_summaries.items():
        click.echo(f"\n{name}:")
        for tm, stats in sorted(summary.items()):
            asr = stats.get("asr", 0)
            click.echo(
                f"  {tm}: ASR={asr:.1%}, tasks={stats.get('total_tasks', '?')}"
            )


def _build_target(cfg: dict[str, Any]) -> Any:
    """Factory: build target from config."""
    target_type = cfg["type"]
    if target_type == "agentdojo":
        from superred.targets.agentdojo_target import AgentDojoTarget

        return AgentDojoTarget(**cfg.get("params", {}))
    elif target_type == "api":
        from superred.targets.api_target import APITarget, APITargetConfig

        return APITarget(APITargetConfig(**cfg.get("params", {})))
    else:
        raise ValueError(f"Unknown target type: {target_type}")


def _build_optimizer(cfg: dict[str, Any]) -> Any:
    """Factory: build optimizer from config."""
    opt_type = cfg["type"]
    if opt_type == "static":
        from superred.optimizers.static import StaticInjection

        return StaticInjection(**cfg.get("params", {}))
    elif opt_type == "llm_mutator":
        from superred.optimizers.llm_mutator import LLMMutator, LLMMutatorConfig

        return LLMMutator(LLMMutatorConfig(**cfg.get("params", {})))
    elif opt_type == "mcts_fuzzer":
        from superred.optimizers.mcts_fuzzer import MCTSFuzzer, MCTSFuzzerConfig

        return MCTSFuzzer(MCTSFuzzerConfig(**cfg.get("params", {})))
    elif opt_type == "rl_attacker":
        from superred.optimizers.rl_wrapper import RLAttackerConfig, RLAttackerWrapper

        return RLAttackerWrapper(RLAttackerConfig(**cfg.get("params", {})))
    elif opt_type == "meta_sequential":
        children = [_build_optimizer(child_cfg) for child_cfg in cfg["children"]]
        from superred.optimizers.meta import SequentialMetaOptimizer

        return SequentialMetaOptimizer(children=children, **cfg.get("params", {}))
    else:
        raise ValueError(f"Unknown optimizer type: {opt_type}")


def _build_task(cfg: dict[str, Any], target: Any) -> Any:
    """Factory: build task module from config.

    If no task config is provided, returns a minimal pass-through task
    that must be bound to the target.
    """
    # Placeholder: users will implement concrete task modules
    raise NotImplementedError(
        "Task module construction from config not yet implemented. "
        "Please provide a TaskModuleInterface instance directly to the Controller."
    )


def _build_threat_models(
    cfg: list[dict[str, Any]], target: Any
) -> list[Any]:
    """Build threat models from config."""
    from superred.core.types.threat_model import Budget, ThreatModel

    tms = []
    for tm_cfg in cfg:
        tms.append(
            ThreatModel(
                allowed_controllables=frozenset(tm_cfg.get("controllables", [])),
                allowed_observables=frozenset(tm_cfg.get("observables", [])),
                allowed_feedback=frozenset(tm_cfg.get("feedback", [])),
                budget=Budget(**tm_cfg.get("budget", {})),
            )
        )
    return tms


if __name__ == "__main__":
    cli()
