"""Security domain tags, domain forests, threat models, and budget definitions."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product


@dataclass(frozen=True, eq=False)
class SecurityDomainTag:
    """A node in a security domain tree/forest.

    Identity is by object reference, not by field values. Two tags with the
    same name are considered distinct objects.
    """

    name: str
    parent: SecurityDomainTag | None = None

    def includes(self, other: SecurityDomainTag) -> bool:
        """True if other is self or a descendant of self."""
        current: SecurityDomainTag | None = other
        while current is not None:
            if current is self:
                return True
            current = current.parent
        return False


class SecurityDomain:
    """Validated, immutable forest of SecurityDomainTags."""

    __slots__ = ("_tags",)

    def __init__(self, tags: frozenset[SecurityDomainTag]) -> None:
        names: set[str] = set()
        for tag in tags:
            if tag.name in names:
                raise ValueError(f"duplicate tag name: {tag.name!r}")
            names.add(tag.name)
            if tag.parent is not None and tag.parent not in tags:
                raise ValueError(
                    f"orphan tag {tag.name!r}: parent {tag.parent.name!r} not in domain"
                )
        object.__setattr__(self, "_tags", tags)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("SecurityDomain is immutable")

    def __delattr__(self, _name: str) -> None:
        raise AttributeError("SecurityDomain is immutable")

    def __repr__(self) -> str:
        names = sorted(t.name for t in self._tags)
        return f"SecurityDomain({{{', '.join(names)}}})"

    @property
    def tags(self) -> frozenset[SecurityDomainTag]:
        return self._tags

    def roots(self) -> frozenset[SecurityDomainTag]:
        return frozenset(t for t in self._tags if t.parent is None)

    def distinct_combinations(self) -> list[frozenset[SecurityDomainTag]]:
        """Generate all antichains as Cartesian product across trees."""
        if not self._tags:
            return [frozenset()]

        trees: dict[SecurityDomainTag, list[SecurityDomainTag]] = {}
        for root in self.roots():
            trees[root] = self._collect_tree(root)

        per_tree_options: list[list[frozenset[SecurityDomainTag]]] = []
        for _root, members in trees.items():
            options = _antichains(members)
            per_tree_options.append(options)

        result: list[frozenset[SecurityDomainTag]] = []
        for combo in product(*per_tree_options):
            merged: frozenset[SecurityDomainTag] = frozenset()
            for part in combo:
                merged = merged | part
            result.append(merged)
        return result

    def _collect_tree(self, root: SecurityDomainTag) -> list[SecurityDomainTag]:
        members = [root]
        for tag in self._tags:
            if tag is not root and root.includes(tag):
                members.append(tag)
        return members


def _antichains(
    tree_members: list[SecurityDomainTag],
) -> list[frozenset[SecurityDomainTag]]:
    """Compute all antichains for one tree.

    An antichain is a set of nodes where no node is an ancestor of any other.
    This includes the empty set, singletons, and multi-element sets of
    mutually incomparable nodes (e.g. siblings).
    """

    def _is_antichain(candidate: frozenset[SecurityDomainTag]) -> bool:
        members = list(candidate)
        for i in range(len(members)):
            for j in range(len(members)):
                if i != j and members[i].includes(members[j]):
                    return False
        return True

    # Generate all subsets of tree_members and filter to antichains.
    result: list[frozenset[SecurityDomainTag]] = []
    n = len(tree_members)
    for mask in range(1 << n):
        subset = frozenset(tree_members[i] for i in range(n) if mask & (1 << i))
        if _is_antichain(subset):
            result.append(subset)
    return result


@dataclass(frozen=True)
class Budget:
    """Resource constraints for an evaluation run."""

    max_iterations: int | None = None
    max_model_calls: int | None = None
    max_tokens: int | None = None
    max_wall_seconds: float | None = None
    max_cost_usd: float | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "max_iterations",
            "max_model_calls",
            "max_tokens",
            "max_wall_seconds",
            "max_cost_usd",
        ):
            value = getattr(self, field_name)
            if value is not None and value < 0:
                raise ValueError(f"{field_name} must not be negative, got {value}")


@dataclass(frozen=True)
class ThreatModel:
    """Budgeted access profile M = (C, O, F, B)."""

    name: str
    controllables: frozenset[str]
    observables: frozenset[str]
    feedback: frozenset[str]
    budget: Budget
