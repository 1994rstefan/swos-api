import json

from swos_cli import __version__
from swos_cli.app import app
from typer.testing import CliRunner

runner = CliRunner()


def test_human_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == f"swos-cli {__version__}\n"


def test_compact_json_version() -> None:
    result = runner.invoke(app, ["--output", "json", "--version"])

    assert result.exit_code == 0
    assert result.stdout == (
        f'{{"ok":true,"data":{{"name":"swos-cli","version":"{__version__}"}}}}\n'
    )
    assert "\x1b" not in result.stdout


def test_pretty_json_has_same_content() -> None:
    compact = runner.invoke(app, ["-o", "json", "--version"])
    pretty = runner.invoke(app, ["--version", "-o", "json-pretty"])

    assert pretty.exit_code == 0
    assert pretty.stdout.startswith("{\n")
    assert json.loads(pretty.stdout) == json.loads(compact.stdout)
    assert "\x1b" not in pretty.stdout


def test_environment_selects_output() -> None:
    result = runner.invoke(app, ["--version"], env={"SWOS_OUTPUT": "json"})

    assert result.exit_code == 0
    assert json.loads(result.stdout)["data"]["name"] == "swos-cli"


def test_cli_output_overrides_environment() -> None:
    result = runner.invoke(
        app,
        ["--version", "--output", "human"],
        env={"SWOS_OUTPUT": "json"},
    )

    assert result.exit_code == 0
    assert result.stdout == f"swos-cli {__version__}\n"


def test_json_configuration_error_is_structured(tmp_path) -> None:  # type: ignore[no-untyped-def]
    result = runner.invoke(
        app,
        ["--version", "-o", "json", "--config", str(tmp_path / "missing.toml")],
    )

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "configuration_error"


def test_dotenv_output_applies_to_configuration_errors(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "SWOS_OUTPUT=json\nSWOS_CONFIG=missing.toml\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"]["code"] == "configuration_error"
    assert result.stderr == ""


def test_json_parser_error_is_structured() -> None:
    result = runner.invoke(app, ["--output", "json", "--timeout", "invalid", "--version"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "cli_usage_error"
    assert result.stderr == ""


def test_json_unknown_option_is_structured() -> None:
    result = runner.invoke(app, ["-ojson-pretty", "--unknown", "--version"])

    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"]["code"] == "cli_usage_error"


def test_config_output_applies_to_parser_errors(tmp_path) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "config.toml"
    config.write_text('[defaults]\noutput = "json"\n', encoding="utf-8")

    result = runner.invoke(
        app,
        ["--config", str(config), "--timeout", "invalid", "--version"],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"]["code"] == "cli_usage_error"


def test_untested_firmware_safety_flags_are_global_options() -> None:
    result = runner.invoke(
        app,
        [
            "--allow-untested-firmware",
            "--allow-untested-firmware-writes",
            "--version",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout.startswith("swos-cli ")
