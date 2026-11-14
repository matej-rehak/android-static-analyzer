from typer.testing import CliRunner

from apkscan import __version__
from apkscan.cli import app

runner = CliRunner()


def testVersionWritePackageVersion():
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.output


def testNoArgumentsShowsHelp():
    result = runner.invoke(app, [])

    assert result.exit_code == 2
    assert "Usage:" in result.output
    assert "version" in result.output
