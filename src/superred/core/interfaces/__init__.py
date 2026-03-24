"""Abstract base classes defining the interfaces between superred modules."""

from superred.core.interfaces.optimizer import OptimizerInterface
from superred.core.interfaces.target import TargetModuleInterface
from superred.core.interfaces.task import TaskModuleInterface

__all__ = [
    "OptimizerInterface",
    "TargetModuleInterface",
    "TaskModuleInterface",
]
