# tests/test_types/test_budget.py
import pytest
from superred.types.budget import BudgetUsage, HierarchicalBudget
from superred.types.security import Budget


class TestBudgetUsage:
    def test_defaults_zero(self):
        u = BudgetUsage()
        assert u.iterations == 0
        assert u.tokens == 0

    def test_mutable(self):
        u = BudgetUsage()
        u.iterations = 5
        assert u.iterations == 5


class TestHierarchicalBudget:
    def test_root_creation(self):
        b = Budget(max_iterations=10, max_tokens=1000)
        hb = HierarchicalBudget(budget=b)
        assert not hb.exhausted

    def test_record_usage(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=2))
        hb.record(iterations=1)
        assert not hb.exhausted
        hb.record(iterations=1)
        assert hb.exhausted

    def test_allocate_child(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=10))
        child = hb.allocate(fraction=0.5)
        assert child._budget.max_iterations == 5

    def test_child_usage_propagates(self):
        hb = HierarchicalBudget(budget=Budget(max_tokens=100))
        child = hb.allocate(fraction=0.5)
        child.record(tokens=30)
        assert hb.usage.tokens == 30

    def test_child_cannot_exceed_parent(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=10))
        child = hb.allocate(fraction=0.3)  # 3 iterations
        child.record(iterations=3)
        assert child.exhausted

    def test_remaining(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=10, max_tokens=1000))
        hb.record(iterations=3, tokens=200)
        r = hb.remaining
        assert r.max_iterations == 7
        assert r.max_tokens == 800
