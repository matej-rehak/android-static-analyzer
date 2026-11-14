import typer

from apkscan import __version__

app = typer.Typer(help="Statická analýza Android APK.", no_args_is_help=True)


@app.callback()
def main() -> None:
    pass


# Vypíše verzi, aby šlo ověřit, která verze nástroje je nainstalovaná.
@app.command()
def version() -> None:
    typer.echo(f"apkscan {__version__}")
