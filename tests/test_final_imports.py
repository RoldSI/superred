# tests/test_final_imports.py
def test_all_public_api():
    """Every public API symbol is importable from the right place."""
    # Top level
    from superred import Target, Task, Optimizer, Judge, SecurityClaim
    from superred import Event, EventResponse, Goal, Trajectory
    from superred import __version__
    assert __version__ == "0.1.0"

    # Controller
    from superred.controller import Controller, ThreatModelSweeper, RunResult, TaskResult, EvalResult

    # Channels
    from superred.channels import channel, Channel, compose, EventBus

    # Proxies
    from superred.proxies import llm_proxy, tool_proxy

    # Claims
    from superred.claims import data_isolation_claim, task_alignment_claim

    # Judges
    from superred.judges import FunctionJudge, RegexJudge, LLMJudge

    # Registry
    from superred.registry.discovery import Registry

    # CLI
    from superred.cli.main import cli


def test_top_level_all_attribute():
    """__all__ is defined and contains expected symbols."""
    import superred
    assert hasattr(superred, "__all__")
    expected = {
        "__version__",
        "Target", "Task", "Optimizer", "Judge", "SecurityClaim", "NotApplicable",
        "Event", "EventResponse", "Goal", "Trajectory",
        "SecurityDomainTag", "ThreatModel", "Budget",
        "ControllableSpec", "Controllable",
        "Observable", "ObservableValue",
        "EvaluationResult", "Score", "OracleBundle",
        "HierarchicalBudget", "PropertyKind", "ClaimVerdict",
    }
    assert expected.issubset(set(superred.__all__))


def test_controller_all_attribute():
    """Controller __all__ covers all re-exports."""
    from superred import controller
    assert hasattr(controller, "__all__")
    expected = {"Controller", "ThreatModelSweeper", "RunResult", "TaskResult", "EvalResult", "StagedRunner"}
    assert expected == set(controller.__all__)


def test_proxies_all_attribute():
    """Proxies __all__ covers all re-exports."""
    from superred import proxies
    assert hasattr(proxies, "__all__")
    expected = {"llm_proxy", "tool_proxy", "replay_proxy"}
    assert expected == set(proxies.__all__)


def test_claims_all_attribute():
    """Claims __all__ covers all re-exports."""
    from superred import claims
    assert hasattr(claims, "__all__")
    expected = {
        "action_alignment_claim",
        "authorized_instruction_following_claim",
        "data_isolation_claim",
        "task_alignment_claim",
    }
    assert expected == set(claims.__all__)


def test_judges_all_attribute():
    """Judges __all__ covers all re-exports."""
    from superred import judges
    assert hasattr(judges, "__all__")
    expected = {"FunctionJudge", "RegexJudge", "LLMJudge"}
    assert expected == set(judges.__all__)
