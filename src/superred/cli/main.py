import click
from superred.registry.discovery import Registry


@click.group()
def cli():
    """SuperRed — modular red-teaming framework."""
    pass


@cli.command()
@click.option("--config", required=True, help="Path to YAML config")
def run(config):
    """Run a single evaluation."""
    from superred.cli.config import load_config

    cfg = load_config(config)
    click.echo(f"Running evaluation: target={cfg.target.name}, optimizer={cfg.optimizer.name}")
    # TODO: wire up controller


@cli.command()
@click.option("--config", required=True, help="Path to YAML config")
def sweep(config):
    """Run threat model sweep."""
    from superred.cli.config import load_config

    cfg = load_config(config)
    click.echo(f"Sweeping threat models: target={cfg.target.name}")
    # TODO: wire up ThreatModelSweeper + controller


@cli.command("list")
@click.argument("group", type=click.Choice(["optimizers", "targets", "tasks"]))
def list_modules(group):
    """List discovered modules."""
    registry = Registry()
    modules = registry.discover(group)
    if not modules:
        click.echo(f"No {group} discovered.")
    else:
        for name in sorted(modules):
            click.echo(f"  {name}")


@cli.command()
@click.option("--config", required=True)
@click.option("--format", "fmt", default="agentbeats")
def export(config, fmt):
    """Export results to external format."""
    click.echo(f"Export to {fmt} format (not yet implemented)")
