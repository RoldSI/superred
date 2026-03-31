"""Abstract interfaces defining the contracts between superred modules."""

from superred.core.interfaces.optimizer import OptimizerInterface
from superred.core.interfaces.target import TargetModuleInterface, TargetRunInterface
from superred.core.interfaces.task import (
    BoundTaskTargetInterface,
    EvaluatedRunInterface,
    OracleBundle,
    SecurityClaim,
    TaskModuleInterface,
)

__all__ = [
    "BoundTaskTargetInterface",
    "EvaluatedRunInterface",
    "OptimizerInterface",
    "OracleBundle",
    "SecurityClaim",
    "TargetModuleInterface",
    "TargetRunInterface",
    "TaskModuleInterface",
]
