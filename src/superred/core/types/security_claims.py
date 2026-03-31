"""Security claim types for the contextual agent security framework.

Claims are target-agnostic predicates over normalised execution context,
action / observation records, and an oracle bundle.  The four first-class
claim families — task alignment, action alignment, authorized instruction
following, and data isolation — come directly from the formalised LLM
security draft.  Attack classes (indirect prompt injection, jailbreak, task
drift, memory poisoning, ...) are represented as violations of one or more
primitive claim families rather than as primitive types themselves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from superred.core.types.threat_model import PropertyKind


@dataclass(frozen=True)
class OracleEvidence:
    """Evidence produced by a single oracle invocation."""

    name: str
    value: Any
    confidence: Optional[float] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ClaimVerdict:
    """The result of evaluating a single security claim."""

    claim_id: str
    property_kind: PropertyKind
    satisfied: bool
    score: float
    evidence: Sequence[OracleEvidence]
    explanation: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
