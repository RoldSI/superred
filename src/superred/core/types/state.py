"""Configuration and state specifications for targets.

Two distinct concepts:

- :class:`ConfigSpec` — pre-run configuration slots. The task sets these
  before a run via ``target.set_config()``. The description documents the
  accepted format.

- :class:`StateSpec` — post-run queryable state. The evaluator queries these
  after a run via ``target.get_state()``. The description documents what the
  value represents.

These are intentionally separate: what you configure before a run is not
the same as what you query after.
"""

from __future__ import annotations

from dataclasses import dataclass

from superred.core.types.security import SecurityDomainTag


@dataclass(frozen=True)
class ConfigSpec:
    """A pre-run configuration slot on a target.

    Used by tasks to set up initial state. Values are always text;
    the description documents the expected format — that is the contract.

    Attributes:
        name: Unique identifier within the target.
        security_domain: Trust boundary this config belongs to.
        description: Documents the accepted format.
    """

    name: str
    security_domain: SecurityDomainTag
    description: str


@dataclass(frozen=True)
class StateSpec:
    """A post-run queryable state on a target.

    Used by the evaluator to query ground-truth state after a run.
    Values are always text; the description documents what the value
    represents.

    Attributes:
        name: Unique identifier within the target.
        description: Documents what this state value represents.
    """

    name: str
    description: str
