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
