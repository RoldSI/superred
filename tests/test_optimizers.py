"""Tests for optimizer implementations."""

from superred.core.interfaces.optimizer import OptimizerInterface
from superred.core.types.feedback import EvaluationResult, FeedbackResult, Score
from superred.core.types.threat_model import InterfaceRole, InterfaceSpec, SecurityDomain
from superred.optimizers.static import StaticInjection


def test_static_injection_satisfies_protocol():
    opt = StaticInjection(injection_text="IGNORE")
    assert isinstance(opt, OptimizerInterface)


def test_static_injection_step():
    opt = StaticInjection(injection_text="ATTACK", target_interface="inject")
    opt.initialize("goal", [], [], None)
    values = opt.step()
    assert len(values) == 1
    assert values[0].name == "inject"
    assert values[0].value == "ATTACK"


def test_static_injection_is_exhausted():
    opt = StaticInjection(injection_text="test")
    opt.initialize("goal", [], [], None)
    assert opt.is_exhausted() is True


def test_static_injection_metadata():
    opt = StaticInjection(injection_text="hello")
    assert opt.get_name() == "Static Injection"
    meta = opt.get_metadata()
    assert meta["type"] == "static_injection"
