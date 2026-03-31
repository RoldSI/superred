"""Abstract base classes defining the interfaces between superred modules."""

from superred.core.interfaces.optimizer import Optimizer
from superred.core.interfaces.target import EventHandler, Target

__all__ = [
    "EventHandler",
    "Optimizer",
    "Target",
]
