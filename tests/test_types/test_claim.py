# tests/test_types/test_claim.py
from superred.types.claim import (
    PropertyKind, ClaimVerdict, OracleEvidence, ContextSnapshot, OracleBundle,
)
from superred.types.goal import Goal


class TestPropertyKind:
    def test_four_families(self):
        assert len(PropertyKind) == 4
        assert PropertyKind.DATA_ISOLATION.name == "DATA_ISOLATION"


class TestClaimVerdict:
    def test_verdict_fields(self):
        v = ClaimVerdict(
            property_kind=PropertyKind.DATA_ISOLATION,
            satisfied=False,
            confidence=0.95,
            evidence=[OracleEvidence(name="leak", value="secret123", confidence=1.0)],
            explanation="Secret found in external output",
        )
        assert not v.satisfied
        assert v.evidence[0].value == "secret123"


class TestOracleBundle:
    def test_bundle(self):
        ob = OracleBundle(
            ground_truth_output="Rome",
            forbidden_actions=["transfer_money"],
            sensitive_data={"api_key": "sk-xxx"},
            source_attribution={"instruction_1": "user"},
        )
        assert ob.sensitive_data["api_key"] == "sk-xxx"


class TestContextSnapshot:
    def test_snapshot(self):
        cs = ContextSnapshot(
            goal=Goal(description="test"),
            trajectory_entries=[],
            task_config={"system_prompt": "You are helpful"},
        )
        assert cs.task_config["system_prompt"] == "You are helpful"
