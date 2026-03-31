# tests/test_types/test_primitives.py
from superred.types.controllable import ControllableSpec, Controllable, RequestAnswerPair
from superred.types.observable import Observable, ObservableValue
from superred.types.goal import Goal
from superred.types.config import ConfigSpec, StateSpec, RuntimeParamSpec
from superred.types.feedback import Score, EvaluationResult, FeedbackResult
from superred.types.security import SecurityDomainTag


class TestControllable:
    def test_spec_frozen(self):
        tag = SecurityDomainTag(name="user")
        spec = ControllableSpec(name="input", security_domain=tag)
        assert spec.name == "input"
        assert spec.value_type == "text"
        assert spec.required is False

    def test_controllable_history(self):
        tag = SecurityDomainTag(name="user")
        spec = ControllableSpec(name="input", security_domain=tag)
        ctrl = Controllable(spec=spec)
        assert ctrl.history == []
        pair = RequestAnswerPair(request="q", answer="a")
        ctrl.history.append(pair)
        assert len(ctrl.history) == 1


class TestObservable:
    def test_observable_spec(self):
        tag = SecurityDomainTag(name="internal")
        obs = Observable(name="system_desc", security_domain=tag, description="desc")
        assert obs.observable_type == "text"

    def test_observable_value(self):
        tag = SecurityDomainTag(name="internal")
        obs = Observable(name="code", security_domain=tag)
        val = ObservableValue(observable=obs, content="print('hello')")
        assert val.content == "print('hello')"


class TestGoal:
    def test_goal(self):
        g = Goal(description="Exfiltrate the secret key")
        assert "secret" in g.description


class TestConfig:
    def test_config_spec(self):
        tag = SecurityDomainTag(name="user")
        cs = ConfigSpec(name="system_prompt", security_domain=tag, description="The prompt")
        assert cs.name == "system_prompt"

    def test_state_spec(self):
        ss = StateSpec(name="final_output", description="Agent's final answer")
        assert ss.name == "final_output"

    def test_runtime_param_spec(self):
        rp = RuntimeParamSpec(name="openai_api_key", description="Key for target LLM")
        assert rp.name == "openai_api_key"


class TestFeedback:
    def test_score(self):
        s = Score(value=0.85, name="primary")
        assert s.value == 0.85

    def test_evaluation_result(self):
        s = Score(value=1.0)
        er = EvaluationResult(success=True, primary_score=s)
        assert er.success is True
        assert er.sub_scores == {}
        assert er.rationale == ""

    def test_feedback_result(self):
        s = Score(value=0.0)
        er = EvaluationResult(success=False, primary_score=s, rationale="blocked")
        fr = FeedbackResult(evaluation=er)
        assert fr.evaluation.rationale == "blocked"
