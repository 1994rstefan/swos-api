import json
from importlib import import_module

from swos_cli import __version__
from swos_core.models import (
    DeviceIdentity,
    PortInfo,
    PortStatistics,
    PortVlanInfo,
    SystemInfo,
    VlanInfo,
    VlanPortMembership,
)
from swos_core.safety import SafetyWarning
from typer.testing import CliRunner

app_module = import_module("swos_cli.app")
app = app_module.app
runner = CliRunner()


class FakeDevice:
    def __init__(
        self,
        identity: DeviceIdentity,
        warnings: tuple[SafetyWarning, ...] = (),
    ) -> None:
        self.identity = identity
        self.warnings = warnings

    def get_system_info(self) -> SystemInfo:
        return SystemInfo(
            identity=self.identity,
            name="Office Switch",
            uptime_seconds=90061,
            current_ip="192.168.88.1",
            static_ip="192.168.88.1",
            mac_address="02:00:00:00:00:01",
            serial_number="TEST1234",
        )

    def get_ports(self) -> tuple[PortInfo, ...]:
        return (
            PortInfo(
                number=1,
                name="Port1",
                enabled=True,
                link_up=True,
                speed_mbps=1000,
                full_duplex=True,
                auto_negotiation=True,
                flow_control=True,
            ),
            PortInfo(
                number=2,
                name="Port2",
                enabled=True,
                link_up=False,
                auto_negotiation=True,
                flow_control=False,
            ),
        )

    def get_port_statistics(self) -> tuple[PortStatistics, ...]:
        return (
            PortStatistics(
                number=1,
                rx_bytes=1234,
                tx_bytes=5678,
                rx_packets=12,
                tx_packets=34,
                rx_errors=0,
                tx_errors=1,
            ),
        )

    def get_port_vlans(self) -> tuple[PortVlanInfo, ...]:
        return (
            PortVlanInfo(
                number=1,
                mode="strict",
                receive="tagged_only",
                default_vlan_id=10,
                force_vlan_id=True,
                egress="preserve",
            ),
        )

    def get_vlans(self) -> tuple[VlanInfo, ...]:
        return (
            VlanInfo(
                vlan_id=10,
                independent_learning=True,
                igmp_snooping=False,
                ports=(
                    VlanPortMembership(port_number=1, mode="strip"),
                    VlanPortMembership(port_number=2, mode="not_member"),
                ),
            ),
        )


class FakeRegistry:
    identity = DeviceIdentity(
        firmware_family="css106",
        product_code="CSS106-5G-1S",
        firmware_version="2.19",
        marketing_name="RB260GS",
        build_id="0x6a181cd5",
    )

    def probe(self, connection):  # type: ignore[no-untyped-def]
        del connection
        return self.identity

    def connect(self, identity, connection, policy):  # type: ignore[no-untyped-def]
        del connection, policy
        return FakeDevice(identity)


def mock_registry(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        app_module.PluginRegistry,
        "discover",
        classmethod(lambda cls: FakeRegistry()),
    )


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


def test_system_show_human_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(app, ["--url", "http://192.0.2.1", "system", "show"])

    assert result.exit_code == 0
    assert "Model: RB260GS (CSS106-5G-1S)" in result.stdout
    assert "Firmware: SwOS 2.19" in result.stdout
    assert "Uptime: 1d 01:01:01" in result.stdout
    assert "Current IP: 192.168.88.1" in result.stdout


def test_system_show_accepts_global_url_after_command(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    after_command = runner.invoke(
        app,
        ["system", "show", "--url", "https://192.0.2.1"],
    )
    between_commands = runner.invoke(
        app,
        ["system", "--url", "https://192.0.2.1", "show"],
    )

    assert after_command.exit_code == 0
    assert between_commands.exit_code == 0
    assert "Model: RB260GS (CSS106-5G-1S)" in after_command.stdout
    assert "Model: RB260GS (CSS106-5G-1S)" in between_commands.stdout


def test_system_show_accepts_all_global_options_after_command(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        [
            "system",
            "show",
            "--url",
            "http://192.0.2.1",
            "--username",
            "admin",
            "--password",
            "secret",
            "--model",
            "RB260GS",
            "--firmware",
            "2.19",
            "--timeout",
            "3",
            "--no-verify-tls",
            "--allow-untested-firmware",
            "-ojson",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["data"]["identity"]["product_code"] == "CSS106-5G-1S"


def test_system_show_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        ["--url", "http://192.0.2.1", "-o", "json", "system", "show"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["data"]["identity"]["product_code"] == "CSS106-5G-1S"
    assert payload["data"]["serial_number"] == "TEST1234"


def test_system_show_requires_url() -> None:
    result = runner.invoke(app, ["system", "show"])

    assert result.exit_code == 2
    assert "A device URL is required" in result.stderr


def test_system_show_checks_configured_model(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        ["--url", "http://192.0.2.1", "--model", "RB260GSP", "system", "show"],
    )

    assert result.exit_code == 2
    assert "does not match detected device" in result.stderr


def test_system_show_includes_firmware_warnings(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class WarningRegistry(FakeRegistry):
        def connect(self, identity, connection, policy):  # type: ignore[no-untyped-def]
            del connection, policy
            warning = SafetyWarning(code="untested_firmware", message="Firmware is untested")
            return FakeDevice(identity, (warning,))

    monkeypatch.setattr(
        app_module.PluginRegistry,
        "discover",
        classmethod(lambda cls: WarningRegistry()),
    )

    result = runner.invoke(
        app,
        ["--url", "http://192.0.2.1", "-o", "json", "system", "show"],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["data"]["warnings"][0]["code"] == "untested_firmware"


def test_port_list_human_output_and_trailing_options(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        ["port", "list", "--url", "http://192.0.2.1"],
    )

    assert result.exit_code == 0
    assert "PORT  NAME" in result.stdout
    assert "Port1" in result.stdout
    assert "1000 Mbps" in result.stdout
    assert "Port2" in result.stdout
    assert "down" in result.stdout


def test_port_list_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    result = runner.invoke(
        app,
        ["port", "list", "--url", "http://192.0.2.1", "-o", "json"],
    )

    assert result.exit_code == 0
    ports = json.loads(result.stdout)["data"]["ports"]
    assert ports[0]["speed_mbps"] == 1000
    assert ports[1]["speed_mbps"] is None


def test_port_stats_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["port", "stats", "--url", "http://192.0.2.1"])
    machine = runner.invoke(
        app,
        ["port", "stats", "--url", "http://192.0.2.1", "-ojson"],
    )

    assert human.exit_code == 0
    assert "RX BYTES" in human.stdout
    assert "1234" in human.stdout
    assert machine.exit_code == 0
    assert json.loads(machine.stdout)["data"]["ports"][0]["tx_errors"] == 1


def test_vlan_ports_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["vlan", "ports", "--url", "http://192.0.2.1"])
    machine = runner.invoke(
        app,
        ["vlan", "ports", "--url", "http://192.0.2.1", "-ojson"],
    )

    assert human.exit_code == 0
    assert "DEFAULT VLAN" in human.stdout
    assert "tagged only" in human.stdout
    assert machine.exit_code == 0
    port = json.loads(machine.stdout)["data"]["ports"][0]
    assert port["mode"] == "strict"
    assert port["force_vlan_id"] is True


def test_vlan_list_human_and_json_output(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    mock_registry(monkeypatch)

    human = runner.invoke(app, ["vlan", "list", "--url", "http://192.0.2.1"])
    machine = runner.invoke(
        app,
        ["vlan", "list", "--url", "http://192.0.2.1", "-ojson"],
    )

    assert human.exit_code == 0
    assert "IGMP SNOOPING" in human.stdout
    assert "1=strip" in human.stdout
    assert machine.exit_code == 0
    vlan = json.loads(machine.stdout)["data"]["vlans"][0]
    assert vlan["vlan_id"] == 10
    assert vlan["ports"][1]["mode"] == "not_member"
