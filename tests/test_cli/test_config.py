import pytest
import yaml

from superred.cli.config import load_config, EvalConfig, OptimizerConfig


class TestLoadConfig:
    def test_basic_config(self, tmp_path):
        config = {
            "target": {"name": "agentdojo", "params": {"suite": "workspace"}},
            "task": {"name": "agentdojo_workspace", "claims": ["data_isolation"]},
            "optimizer": {"name": "mcts_fuzzer", "params": {"iterations": 15}},
            "threat_models": {"sweep": True, "budget": {"max_iterations": 25}},
            "output": {"dir": "results/exp1", "format": "json"},
        }
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(config))
        cfg = load_config(str(path))
        assert cfg.target.name == "agentdojo"
        assert cfg.target.params["suite"] == "workspace"
        assert cfg.optimizer.name == "mcts_fuzzer"
        assert cfg.task.claims == ["data_isolation"]
        assert cfg.threat_models.sweep is True
        assert cfg.output.dir == "results/exp1"

    def test_nested_optimizer_children(self, tmp_path):
        config = {
            "target": {"name": "test"},
            "task": {"name": "test"},
            "optimizer": {
                "name": "meta",
                "params": {
                    "children": [
                        {"name": "mcts", "params": {"iterations": 15}},
                        {"name": "llm_mutator", "params": {"iterations": 10}},
                    ]
                },
            },
        }
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(config))
        cfg = load_config(str(path))
        assert cfg.optimizer.name == "meta"
        assert len(cfg.optimizer.children) == 2
        assert cfg.optimizer.children[0].name == "mcts"

    def test_minimal_config(self, tmp_path):
        config = {
            "target": {"name": "test"},
            "task": {"name": "test"},
            "optimizer": {"name": "static"},
        }
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(config))
        cfg = load_config(str(path))
        assert cfg.threat_models.sweep is False
        assert cfg.output.format == "json"
