from __future__ import annotations

import importlib.metadata
from typing import Any


class Registry:
    """Discovers superred modules via entry points."""

    _GROUPS = {
        "optimizers": "superred.optimizers",
        "targets": "superred.targets",
        "tasks": "superred.tasks",
    }

    def __init__(self) -> None:
        self._cache: dict[str, dict[str, Any]] = {}

    def discover(self, group: str) -> dict[str, Any]:
        """Discover all modules in a group. Returns {name: class}."""
        if group in self._cache:
            return self._cache[group]

        ep_group = self._GROUPS.get(group, group)
        result: dict[str, Any] = {}
        try:
            eps = importlib.metadata.entry_points(group=ep_group)
            for ep in eps:
                result[ep.name] = ep.load()
        except Exception:
            pass

        self._cache[group] = result
        return result

    def discover_optimizers(self) -> dict[str, Any]:
        return self.discover("optimizers")

    def discover_targets(self) -> dict[str, Any]:
        return self.discover("targets")

    def discover_tasks(self) -> dict[str, Any]:
        return self.discover("tasks")

    def get(self, group: str, name: str) -> Any:
        """Get a specific module by group and name. Raises KeyError if not found."""
        modules = self.discover(group)
        if name not in modules:
            raise KeyError(f"Module {name!r} not found in group {group!r}")
        return modules[name]

    def list_all(self) -> dict[str, list[str]]:
        """List all discovered module names by group."""
        return {
            group: sorted(self.discover(group).keys()) for group in self._GROUPS
        }
