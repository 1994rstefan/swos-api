from pathlib import Path

import pytest
from swos_cli.config import ConfigurationError, load_configuration
from swos_cli.output import OutputFormat


def write_config(path: Path) -> None:
    path.write_text(
        """
[defaults]
device = "office"
output = "human"
username = "from-config"
timeout = 1

[devices.office]
url = "http://192.0.2.1"
model = "css106-5g-1s"
firmware = "2.19"
timeout = 2
""".strip(),
        encoding="utf-8",
    )


def test_precedence_order(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    write_config(config_path)
    (tmp_path / ".env").write_text(
        "SWOS_USERNAME=from-dotenv\nSWOS_TIMEOUT=3\n",
        encoding="utf-8",
    )

    resolved = load_configuration(
        {"timeout": 5},
        config_path=config_path,
        environ={"SWOS_USERNAME": "from-process", "SWOS_TIMEOUT": "4"},
        cwd=tmp_path,
    )

    assert resolved.settings.device == "office"
    assert str(resolved.settings.url) == "http://192.0.2.1/"
    assert resolved.settings.username == "from-process"
    assert resolved.settings.timeout == 5
    assert resolved.settings.model == "css106-5g-1s"


def test_dotenv_can_select_relative_config_path(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.toml"
    write_config(config_path)
    (tmp_path / ".env").write_text(
        "SWOS_CONFIG=settings.toml\nSWOS_OUTPUT=json-pretty\n",
        encoding="utf-8",
    )

    resolved = load_configuration(environ={}, cwd=tmp_path)

    assert resolved.config_path == config_path
    assert resolved.settings.output is OutputFormat.JSON_PRETTY


def test_process_environment_overrides_dotenv(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("SWOS_OUTPUT=json-pretty\n", encoding="utf-8")

    resolved = load_configuration(environ={"SWOS_OUTPUT": "json"}, cwd=tmp_path)

    assert resolved.settings.output is OutputFormat.JSON


def test_cli_device_selects_profile(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[defaults]
device = "first"

[devices.first]
url = "http://192.0.2.1"

[devices.second]
url = "http://192.0.2.2"
""".strip(),
        encoding="utf-8",
    )

    resolved = load_configuration(
        {"device": "second"},
        config_path=config_path,
        environ={},
        cwd=tmp_path,
    )

    assert resolved.settings.device == "second"
    assert str(resolved.settings.url) == "http://192.0.2.2/"


def test_cli_values_override_all_other_layers(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    write_config(config_path)

    resolved = load_configuration(
        {
            "url": "http://192.0.2.99",
            "username": "from-cli",
            "output": "json",
            "verify_tls": False,
        },
        config_path=config_path,
        environ={"SWOS_USERNAME": "from-process"},
        cwd=tmp_path,
    )

    assert str(resolved.settings.url) == "http://192.0.2.99/"
    assert resolved.settings.username == "from-cli"
    assert resolved.settings.output is OutputFormat.JSON
    assert resolved.settings.verify_tls is False


def test_missing_explicit_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        load_configuration(config_path=tmp_path / "missing.toml", environ={}, cwd=tmp_path)


def test_unknown_device_profile_is_an_error(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    write_config(config_path)

    with pytest.raises(ConfigurationError, match="was not found"):
        load_configuration(
            {"device": "missing"},
            config_path=config_path,
            environ={},
            cwd=tmp_path,
        )


def test_device_selection_requires_a_configuration_profile(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="was not found"):
        load_configuration(
            {"device": "missing"},
            environ={},
            cwd=tmp_path,
        )


def test_invalid_setting_does_not_echo_secret(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[defaults]
password = "top-secret"
timeout = -1
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as error:
        load_configuration(config_path=config_path, environ={}, cwd=tmp_path)

    assert "top-secret" not in str(error.value)
