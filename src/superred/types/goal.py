# src/superred/types/goal.py
from dataclasses import dataclass

@dataclass(frozen=True)
class Goal:
    description: str
