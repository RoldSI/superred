import pytest
from superred.types.security import SecurityDomainTag, SecurityDomain, ThreatModel, Budget


class TestSecurityDomainTag:
    def test_root_tag(self):
        tag = SecurityDomainTag(name="user")
        assert tag.name == "user"
        assert tag.parent is None

    def test_child_tag(self):
        parent = SecurityDomainTag(name="external")
        child = SecurityDomainTag(name="web_search", parent=parent)
        assert child.parent is parent

    def test_includes_self(self):
        tag = SecurityDomainTag(name="user")
        assert tag.includes(tag)

    def test_includes_descendant(self):
        root = SecurityDomainTag(name="external")
        child = SecurityDomainTag(name="tool", parent=root)
        grandchild = SecurityDomainTag(name="web", parent=child)
        assert root.includes(child)
        assert root.includes(grandchild)
        assert not child.includes(root)

    def test_frozen(self):
        tag = SecurityDomainTag(name="user")
        with pytest.raises(AttributeError):
            tag.name = "other"


class TestSecurityDomain:
    def test_empty_domain(self):
        domain = SecurityDomain(frozenset())
        assert domain.roots() == frozenset()

    def test_rejects_orphan(self):
        parent = SecurityDomainTag(name="parent")
        child = SecurityDomainTag(name="child", parent=parent)
        with pytest.raises(ValueError, match="orphan"):
            SecurityDomain(frozenset({child}))

    def test_rejects_duplicate_names(self):
        a = SecurityDomainTag(name="dup")
        b = SecurityDomainTag(name="dup")
        with pytest.raises(ValueError, match="duplicate"):
            SecurityDomain(frozenset({a, b}))

    def test_roots(self):
        r1 = SecurityDomainTag(name="user")
        r2 = SecurityDomainTag(name="external")
        c1 = SecurityDomainTag(name="web", parent=r2)
        domain = SecurityDomain(frozenset({r1, r2, c1}))
        assert domain.roots() == frozenset({r1, r2})

    def test_distinct_combinations_single_root(self):
        tag = SecurityDomainTag(name="user")
        domain = SecurityDomain(frozenset({tag}))
        combos = domain.distinct_combinations()
        names = [frozenset(t.name for t in c) for c in combos]
        assert frozenset() in names
        assert frozenset({"user"}) in names
        assert len(combos) == 2

    def test_distinct_combinations_forest(self):
        r1 = SecurityDomainTag(name="user")
        r2 = SecurityDomainTag(name="ext")
        domain = SecurityDomain(frozenset({r1, r2}))
        combos = domain.distinct_combinations()
        # Two independent roots: {}, {user}, {ext}, {user, ext}
        assert len(combos) == 4

    def test_distinct_combinations_branching(self):
        root = SecurityDomainTag(name="ext")
        child_a = SecurityDomainTag(name="web", parent=root)
        child_b = SecurityDomainTag(name="email", parent=root)
        domain = SecurityDomain(frozenset({root, child_a, child_b}))
        combos = domain.distinct_combinations()
        names = [frozenset(t.name for t in c) for c in combos]
        assert frozenset() in names
        assert frozenset({"ext"}) in names
        assert frozenset({"web"}) in names
        assert frozenset({"email"}) in names
        assert frozenset({"web", "email"}) in names  # siblings
        assert len(combos) == 5

    def test_immutability_setattr(self):
        tag = SecurityDomainTag(name="user")
        domain = SecurityDomain(frozenset({tag}))
        with pytest.raises(AttributeError, match="immutable"):
            domain.x = 42

    def test_immutability_delattr(self):
        tag = SecurityDomainTag(name="user")
        domain = SecurityDomain(frozenset({tag}))
        with pytest.raises(AttributeError, match="immutable"):
            del domain._tags

    def test_repr(self):
        r = SecurityDomainTag(name="ext")
        c = SecurityDomainTag(name="web", parent=r)
        domain = SecurityDomain(frozenset({r, c}))
        assert repr(domain) == "SecurityDomain({ext, web})"


class TestThreatModel:
    def test_frozen(self):
        tm = ThreatModel(
            name="user_only",
            controllables=frozenset({"user_input"}),
            observables=frozenset({"final_output"}),
            feedback=frozenset({"score"}),
            budget=Budget(max_iterations=10),
        )
        assert tm.name == "user_only"
        with pytest.raises(AttributeError):
            tm.name = "other"


class TestThreatModelFields:
    def test_field_access(self):
        b = Budget(max_iterations=10)
        tm = ThreatModel(
            name="multi",
            controllables=frozenset({"user_input", "system_prompt"}),
            observables=frozenset({"final_output"}),
            feedback=frozenset({"score", "reason"}),
            budget=b,
        )
        assert tm.name == "multi"
        assert "user_input" in tm.controllables
        assert "system_prompt" in tm.controllables
        assert tm.observables == frozenset({"final_output"})
        assert tm.feedback == frozenset({"score", "reason"})
        assert tm.budget is b
        assert tm.budget.max_iterations == 10


class TestBudget:
    def test_defaults_none(self):
        b = Budget()
        assert b.max_iterations is None
        assert b.max_tokens is None

    def test_partial(self):
        b = Budget(max_iterations=25, max_cost_usd=5.0)
        assert b.max_iterations == 25
        assert b.max_cost_usd == 5.0
        assert b.max_model_calls is None

    def test_frozen(self):
        b = Budget(max_iterations=10)
        with pytest.raises(AttributeError):
            b.max_iterations = 20

    def test_rejects_negative_iterations(self):
        with pytest.raises(ValueError, match="max_iterations"):
            Budget(max_iterations=-1)

    def test_rejects_negative_cost(self):
        with pytest.raises(ValueError, match="max_cost_usd"):
            Budget(max_cost_usd=-0.5)

    def test_allows_zero(self):
        b = Budget(max_iterations=0, max_cost_usd=0.0)
        assert b.max_iterations == 0
        assert b.max_cost_usd == 0.0
