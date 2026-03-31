"""YAML config loading with ${ENV_VAR} expansion."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{(\w+)\}")


def _expand_env_vars(value: Any) -> Any:
    """Recursively expand ${ENV_VAR} references in config values."""
    if isinstance(value, str):

        def replacer(match: re.Match) -> str:
            var_name = match.group(1)
            return os.environ.get(var_name, match.group(0))

        return _ENV_PATTERN.sub(replacer, value)
    elif isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_expand_env_vars(v) for v in value]
    return value


def load_config(path: str | Path) -> dict[str, Any]:
    """Load a YAML config file with environment variable expansion."""
    with open(path) as f:
        raw = yaml.safe_load(f)
    return _expand_env_vars(raw)
