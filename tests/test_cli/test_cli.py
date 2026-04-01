import pytest
from click.testing import CliRunner
from superred.cli.main import cli


class TestCLI:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "SuperRed" in result.output

    def test_list_optimizers(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["list", "optimizers"])
        assert result.exit_code == 0

    def test_list_invalid_group(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["list", "invalid"])
        assert result.exit_code != 0
