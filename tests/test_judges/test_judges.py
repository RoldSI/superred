"""Tests for FunctionJudge, RegexJudge, and LLMJudge."""

import pytest

from superred.judges.function_judge import FunctionJudge
from superred.judges.regex_judge import RegexJudge
from superred.judges.llm_judge import LLMJudge
from superred.types import (
    Goal,
    OracleBundle,
    Trajectory,
    TrajectoryEntry,
    MODEL_RESPONSE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_trajectory(*contents: str) -> Trajectory:
    """Build a Trajectory populated with MODEL_RESPONSE entries."""
    t = Trajectory()
    for c in contents:
        # Bypass async emit by directly appending (tests only).
        t._entries.append(TrajectoryEntry(entry_type=MODEL_RESPONSE, content=c))
    return t


GOAL = Goal(description="test goal")
ORACLE = OracleBundle()


# ---------------------------------------------------------------------------
# FunctionJudge
# ---------------------------------------------------------------------------

class TestFunctionJudge:
    @pytest.mark.asyncio
    async def test_success_when_fn_returns_true(self):
        judge = FunctionJudge(fn=lambda traj, oracle: True)
        result = await judge.evaluate(GOAL, Trajectory(), ORACLE)
        assert result.success is True
        assert result.primary_score.value == 1.0

    @pytest.mark.asyncio
    async def test_failure_when_fn_returns_false(self):
        judge = FunctionJudge(fn=lambda traj, oracle: False)
        result = await judge.evaluate(GOAL, Trajectory(), ORACLE)
        assert result.success is False
        assert result.primary_score.value == 0.0

    @pytest.mark.asyncio
    async def test_fn_receives_trajectory_and_oracle(self):
        captured = {}

        def spy(traj, oracle):
            captured["traj"] = traj
            captured["oracle"] = oracle
            return True

        traj = _make_trajectory("hello")
        oracle = OracleBundle(ground_truth_output="expected")
        judge = FunctionJudge(fn=spy)
        await judge.evaluate(GOAL, traj, oracle)

        assert captured["traj"] is traj
        assert captured["oracle"] is oracle


# ---------------------------------------------------------------------------
# RegexJudge
# ---------------------------------------------------------------------------

class TestRegexJudge:
    @pytest.mark.asyncio
    async def test_pattern_found(self):
        judge = RegexJudge(pattern=r"secret\d+")
        traj = _make_trajectory("the secret123 is here")
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is True
        assert result.primary_score.value == 1.0
        assert "found" in result.rationale

    @pytest.mark.asyncio
    async def test_pattern_not_found(self):
        judge = RegexJudge(pattern=r"secret\d+")
        traj = _make_trajectory("nothing interesting")
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is False
        assert result.primary_score.value == 0.0
        assert "not found" in result.rationale

    @pytest.mark.asyncio
    async def test_expect_no_match_success(self):
        judge = RegexJudge(pattern=r"forbidden", expect_match=False)
        traj = _make_trajectory("all clear")
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is True
        assert result.primary_score.value == 1.0

    @pytest.mark.asyncio
    async def test_expect_no_match_failure(self):
        judge = RegexJudge(pattern=r"forbidden", expect_match=False)
        traj = _make_trajectory("this is forbidden content")
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is False
        assert result.primary_score.value == 0.0

    @pytest.mark.asyncio
    async def test_empty_trajectory(self):
        judge = RegexJudge(pattern=r"anything")
        result = await judge.evaluate(GOAL, Trajectory(), ORACLE)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_non_string_content_skipped(self):
        """Non-string content entries should not cause errors."""
        judge = RegexJudge(pattern=r"match")
        traj = Trajectory()
        traj._entries.append(
            TrajectoryEntry(entry_type=MODEL_RESPONSE, content=42)
        )
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is False


# ---------------------------------------------------------------------------
# LLMJudge
# ---------------------------------------------------------------------------

class TestLLMJudge:
    @pytest.mark.asyncio
    async def test_successful_evaluation(self):
        def judge_fn(goal_desc: str, content: str) -> tuple[bool, float]:
            return True, 0.95

        judge = LLMJudge(judge_fn=judge_fn)
        traj = _make_trajectory("some output")
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is True
        assert result.primary_score.value == 0.95

    @pytest.mark.asyncio
    async def test_failed_evaluation(self):
        def judge_fn(goal_desc: str, content: str) -> tuple[bool, float]:
            return False, 0.2

        judge = LLMJudge(judge_fn=judge_fn)
        traj = _make_trajectory("bad output")
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is False
        assert result.primary_score.value == 0.2

    @pytest.mark.asyncio
    async def test_receives_goal_and_content(self):
        captured = {}

        def spy(goal_desc: str, content: str) -> tuple[bool, float]:
            captured["goal"] = goal_desc
            captured["content"] = content
            return True, 1.0

        traj = _make_trajectory("line1", "line2")
        goal = Goal(description="my goal")
        judge = LLMJudge(judge_fn=spy)
        await judge.evaluate(goal, traj, ORACLE)

        assert captured["goal"] == "my goal"
        assert captured["content"] == "line1\nline2"

    @pytest.mark.asyncio
    async def test_retry_on_exception_then_succeed(self):
        call_count = 0

        def flaky(goal_desc: str, content: str) -> tuple[bool, float]:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("transient failure")
            return True, 0.8

        judge = LLMJudge(judge_fn=flaky, max_retries=3)
        traj = _make_trajectory("data")
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is True
        assert result.primary_score.value == 0.8
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_all_retries_exhausted(self):
        call_count = 0

        def always_fail(goal_desc: str, content: str) -> tuple[bool, float]:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("permanent failure")

        judge = LLMJudge(judge_fn=always_fail, max_retries=3)
        traj = _make_trajectory("data")
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is False
        assert result.primary_score.value == 0.0
        assert "failed after retries" in result.rationale
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_custom_max_retries(self):
        call_count = 0

        def always_fail(goal_desc: str, content: str) -> tuple[bool, float]:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("fail")

        judge = LLMJudge(judge_fn=always_fail, max_retries=5)
        traj = _make_trajectory("data")
        result = await judge.evaluate(GOAL, traj, ORACLE)
        assert result.success is False
        assert call_count == 5
