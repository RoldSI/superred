"""Abstract base classes defining the interfaces between superred modules."""

from superred.core.interfaces.optimizer import Optimizer
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.interfaces.target import EventHandler, Target
from superred.core.interfaces.task import NotApplicable, Task

__all__ = [
    "EventHandler",
    "NotApplicable",
    "Optimizer",
    "SecurityClaim",
    "Target",
    "Task",
]
