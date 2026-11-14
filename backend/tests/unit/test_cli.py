from typer.testing import CliRunner

from apkscan import __version__
from apkscan.cli import app

runner = CliRunner()


# Příkaz version skončí bez chyby a vypíše aktuální verzi balíčku.
def test_version_prints_package_version():
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.output


# Bez argumentů se místo chyby vypíše nápověda se seznamem příkazů.
def test_no_arguments_shows_help():
    result = runner.invoke(app, [])

    assert "version" in result.output
