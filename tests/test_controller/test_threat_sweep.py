"""Tests for ThreatModelSweeper."""

import pytest

from superred.controller.threat_sweep import ThreatModelSweeper
from superred.interfaces.target import Target
from superred.types import (
    ControllableSpec,
    Observable,
    ObservableValue,
    ConfigSpec,
    StateSpec,
    RuntimeParamSpec,
    SecurityDomainTag,
)
from superred.types.security import Budget, ThreatModel
from superred.channels.channel import AsyncSender, AsyncReceiver
from superred.types import Event, EventResponse


# ---------------------------------------------------------------------------
# Helper stub targets
# ---------------------------------------------------------------------------

class EmptyTarget(Target):
    """Target with no controllables or observables."""

    def controllable_specs(self):
        return []

    def observable_specs(self):
        return []

    def config_specs(self):
        return []

    def state_specs(self):
        return []

    def runtime_params(self):
        return []

    async def set_config(self, name, value):
        pass

    async def get_observables(self):
        return []

    async def get_state(self, name):
        return ""

    async def run(self, send_event, recv_response):
        pass


class SingleDomainTarget(Target):
    """Target with one domain tag on both a controllable and an observable."""

    def __init__(self):
        self._tag = SecurityDomainTag(name="user")
        self._ctrl = ControllableSpec(name="user_input", security_domain=self._tag)
        self._obs = Observable(name="final_output", security_domain=self._tag)

    def controllable_specs(self):
        return [self._ctrl]

    def observable_specs(self):
        return [self._obs]

    def config_specs(self):
        return []

    def state_specs(self):
        return []

    def runtime_params(self):
        return []

    async def set_config(self, name, value):
        pass

    async def get_observables(self):
        return []

    async def get_state(self, name):
        return ""

    async def run(self, send_event, recv_response):
        pass


class TwoDomainTarget(Target):
    """Target with two independent domain tags (separate trees)."""

    def __init__(self):
        self._tag_user = SecurityDomainTag(name="user")
        self._tag_tool = SecurityDomainTag(name="tool")
        self._ctrl_user = ControllableSpec(
            name="user_input", security_domain=self._tag_user
        )
        self._ctrl_tool = ControllableSpec(
            name="tool_input", security_domain=self._tag_tool
        )
        self._obs_user = Observable(
            name="user_output", security_domain=self._tag_user
        )
        self._obs_tool = Observable(
            name="tool_output", security_domain=self._tag_tool
        )

    def controllable_specs(self):
        return [self._ctrl_user, self._ctrl_tool]

    def observable_specs(self):
        return [self._obs_user, self._obs_tool]

    def config_specs(self):
        return []

    def state_specs(self):
        return []

    def runtime_params(self):
        return []

    async def set_config(self, name, value):
        pass

    async def get_observables(self):
        return []

    async def get_state(self, name):
        return ""

    async def run(self, send_event, recv_response):
        pass


class HierarchicalTarget(Target):
    """Target with a parent tag and two child tags (one tree with branching)."""

    def __init__(self):
        self._root = SecurityDomainTag(name="external")
        self._child_web = SecurityDomainTag(name="web", parent=self._root)
        self._child_email = SecurityDomainTag(name="email", parent=self._root)
        self._ctrl_web = ControllableSpec(
            name="web_input", security_domain=self._child_web
        )
        self._ctrl_email = ControllableSpec(
            name="email_input", security_domain=self._child_email
        )
        self._obs = Observable(
            name="system_output", security_domain=self._root
        )

    def controllable_specs(self):
        return [self._ctrl_web, self._ctrl_email]

    def observable_specs(self):
        return [self._obs]

    def config_specs(self):
        return []

    def state_specs(self):
        return []

    def runtime_params(self):
        return []

    async def set_config(self, name, value):
        pass

    async def get_observables(self):
        return []

    async def get_state(self, name):
        return ""

    async def run(self, send_event, recv_response):
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

BUDGET = Budget(max_iterations=10)


class TestEmptyTarget:
    def test_empty_target_single_threat_model(self):
        target = EmptyTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        assert len(models) == 1
        assert models[0].name == "empty"
        assert models[0].controllables == frozenset()
        assert models[0].observables == frozenset()
        assert models[0].feedback == frozenset()
        assert models[0].budget is BUDGET


class TestSingleDomain:
    def test_produces_two_threat_models(self):
        """One root tag -> 2 antichains: empty and {user}."""
        target = SingleDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        assert len(models) == 2

    def test_narrowest_first(self):
        target = SingleDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        # First model should be the narrowest (no controllables/observables)
        sizes = [len(m.controllables) + len(m.observables) for m in models]
        assert sizes == sorted(sizes)

    def test_empty_combination_has_no_specs(self):
        target = SingleDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        # The narrowest model (from the empty antichain) should have nothing
        narrow = models[0]
        assert narrow.controllables == frozenset()
        assert narrow.observables == frozenset()

    def test_full_combination_has_all_specs(self):
        target = SingleDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        widest = models[-1]
        assert "user_input" in widest.controllables
        assert "final_output" in widest.observables

    def test_budget_propagated(self):
        target = SingleDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        for m in models:
            assert m.budget is BUDGET


class TestTwoIndependentDomains:
    def test_produces_four_threat_models(self):
        """Two independent roots -> 2*2 = 4 antichains."""
        target = TwoDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        assert len(models) == 4

    def test_ordering_narrowest_to_widest(self):
        target = TwoDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        sizes = [len(m.controllables) + len(m.observables) for m in models]
        assert sizes == sorted(sizes)

    def test_names_are_sorted_tags(self):
        target = TwoDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        names = {m.name for m in models}
        # The empty antichain should have name "none"
        assert "none" in names
        # Single-tag antichains
        assert "tool" in names
        assert "user" in names
        # Combined antichain
        assert "tool+user" in names

    def test_each_combination_covers_correct_specs(self):
        target = TwoDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        by_name = {m.name: m for m in models}

        assert by_name["none"].controllables == frozenset()
        assert by_name["none"].observables == frozenset()

        assert by_name["user"].controllables == frozenset({"user_input"})
        assert by_name["user"].observables == frozenset({"user_output"})

        assert by_name["tool"].controllables == frozenset({"tool_input"})
        assert by_name["tool"].observables == frozenset({"tool_output"})

        assert by_name["tool+user"].controllables == frozenset(
            {"user_input", "tool_input"}
        )
        assert by_name["tool+user"].observables == frozenset(
            {"user_output", "tool_output"}
        )


class TestHierarchicalDomain:
    def test_hierarchy_produces_correct_count(self):
        """One tree with root + 2 children -> 5 antichains."""
        target = HierarchicalTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        # Antichains: {}, {external}, {web}, {email}, {web,email}
        assert len(models) == 5

    def test_parent_tag_includes_child_specs(self):
        """The 'external' tag should include specs of its children."""
        target = HierarchicalTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        by_name = {m.name: m for m in models}

        # external includes all children
        ext = by_name["external"]
        assert "web_input" in ext.controllables
        assert "email_input" in ext.controllables
        assert "system_output" in ext.observables

    def test_child_tag_covers_only_own_specs(self):
        target = HierarchicalTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        by_name = {m.name: m for m in models}

        # web only covers web_input, not email_input
        web = by_name["web"]
        assert "web_input" in web.controllables
        assert "email_input" not in web.controllables
        # web does NOT include the parent's observable (system_output has tag=external)
        assert "system_output" not in web.observables

    def test_ordering(self):
        target = HierarchicalTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        sizes = [len(m.controllables) + len(m.observables) for m in models]
        assert sizes == sorted(sizes)


class TestFeedbackAlwaysEmpty:
    def test_feedback_is_empty(self):
        target = TwoDomainTarget()
        models = ThreatModelSweeper.generate(target, BUDGET)
        for m in models:
            assert m.feedback == frozenset()
