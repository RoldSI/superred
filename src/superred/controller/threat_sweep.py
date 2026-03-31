"""Automatic threat-model generation from a target's specifications."""

from __future__ import annotations

from superred.interfaces.target import Target
from superred.types.security import (
    Budget,
    SecurityDomain,
    SecurityDomainTag,
    ThreatModel,
)


class ThreatModelSweeper:
    """Generate a family of :class:`ThreatModel` instances from a target.

    The sweeper collects all :class:`SecurityDomainTag` objects referenced by the
    target's controllable and observable specs (plus their ancestor tags),
    builds a :class:`SecurityDomain`, and enumerates every distinct antichain
    combination.  Each combination becomes a :class:`ThreatModel` whose
    controllable / observable names are those specs whose tag is *included*
    by at least one tag in the combination.
    """

    @staticmethod
    def generate(target: Target, base_budget: Budget) -> list[ThreatModel]:
        """Return threat models ordered narrowest (fewest specs) to widest."""

        # -- 1. Collect all unique tags (by identity) from specs + ancestors --
        tags: set[SecurityDomainTag] = set()

        for spec in target.controllable_specs():
            current: SecurityDomainTag | None = spec.security_domain
            while current is not None:
                tags.add(current)
                current = current.parent

        for obs in target.observable_specs():
            current = obs.security_domain
            while current is not None:
                tags.add(current)
                current = current.parent

        # -- 2. Handle the empty case --
        if not tags:
            return [
                ThreatModel(
                    name="empty",
                    controllables=frozenset(),
                    observables=frozenset(),
                    feedback=frozenset(),
                    budget=base_budget,
                )
            ]

        # -- 3. Build domain and enumerate antichains --
        domain = SecurityDomain(frozenset(tags))
        combinations = domain.distinct_combinations()

        # -- 4. Map each antichain → ThreatModel --
        threat_models: list[ThreatModel] = []
        for combo in combinations:
            ctrl_names = frozenset(
                s.name
                for s in target.controllable_specs()
                if s.security_domain in combo
                or any(t.includes(s.security_domain) for t in combo)
            )
            obs_names = frozenset(
                o.name
                for o in target.observable_specs()
                if o.security_domain in combo
                or any(t.includes(o.security_domain) for t in combo)
            )
            name = (
                "+".join(sorted(t.name for t in combo)) if combo else "none"
            )
            threat_models.append(
                ThreatModel(
                    name=name,
                    controllables=ctrl_names,
                    observables=obs_names,
                    feedback=frozenset(),
                    budget=base_budget,
                )
            )

        # -- 5. Sort narrowest → widest --
        threat_models.sort(
            key=lambda tm: len(tm.controllables) + len(tm.observables)
        )
        return threat_models
