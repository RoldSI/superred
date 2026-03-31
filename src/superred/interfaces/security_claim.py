"""SecurityClaim — a composable collection of evaluation tasks."""

from __future__ import annotations

from typing import Generic, Iterable, Iterator, TypeVar

from superred.interfaces.target import Target
from superred.interfaces.task import Task

T_Target = TypeVar("T_Target", bound=Target)


class SecurityClaim(Generic[T_Target]):
    """An iterable collection of tasks that constitute a security claim.

    Created via the ``from_tasks`` or ``from_claims`` factory methods.
    Claims can be composed: ``from_claims`` lazily chains multiple claims.
    """

    def __init__(self) -> None:
        raise TypeError("Use from_tasks() or from_claims()")

    @classmethod
    def from_tasks(cls, tasks: Iterable[Task[T_Target]]) -> SecurityClaim[T_Target]:
        """Create a claim from an iterable of tasks."""
        instance: SecurityClaim[T_Target] = object.__new__(cls)
        instance._tasks: list[Task[T_Target]] = list(tasks)
        instance._claims: list[SecurityClaim[T_Target]] = []
        return instance

    @classmethod
    def from_claims(
        cls, claims: Iterable[SecurityClaim[T_Target]]
    ) -> SecurityClaim[T_Target]:
        """Compose multiple claims into one (lazily chains iteration)."""
        instance: SecurityClaim[T_Target] = object.__new__(cls)
        instance._tasks: list[Task[T_Target]] = []
        instance._claims: list[SecurityClaim[T_Target]] = list(claims)
        return instance

    def __iter__(self) -> Iterator[Task[T_Target]]:
        yield from self._tasks
        for claim in self._claims:
            yield from claim
