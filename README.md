# swos-api

An independent, device-agnostic Python API for managing MikroTik SwOS devices.

> [!WARNING]
> The project is in pre-alpha development. Device support is deliberately
> limited to exact hardware and firmware combinations listed below.

## Architecture

This monorepo contains independently versioned Python distributions:

- `swos-core`: public API, transport, plugin contracts, and firmware safeguards
- `swos-cli`: command-line client built exclusively on `swos-core`
- `swos-device-css106`: CSS106 device support
- a future `swos-ansible` package will use the same core API

The CLI and future Ansible integration never contain device-specific HTTP
logic. Device packages are discovered through Python entry points and declare
the exact model and firmware combinations they support.

See [the architecture documentation](docs/architecture.md) for details.

## Development setup

Python 3.11 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Run the initial CLI:

```bash
swosctl --version
swosctl -o json --version
swosctl -o json-pretty --version
swosctl --device office system show
swosctl system show --device office
swosctl system rename "Office Switch" --device office
swosctl port list --device office
swosctl port rename 1 Uplink --device office
swosctl port configure 5 --flow-control on --device office
swosctl port configure 5 --negotiation forced --speed-bps 100000000 --duplex full --device office
swosctl port stats --device office
swosctl port stats --full --device office
swosctl sfp show --device office
swosctl forwarding show --device office
swosctl host list --device office
swosctl igmp list --device office
swosctl acl list --device office
swosctl rstp show --device office
swosctl snmp show --device office
swosctl snmp metadata set --contact "Network Operations" --device office
swosctl snmp metadata set --location "" --device office
swosctl vlan ports --device office
swosctl vlan list --device office
```

Global options may be placed before, between, or after command names. The two
`system show` forms above are equivalent.

Writes remain restricted to exact supported firmware unless the invocation
passes `--allow-untested-firmware-writes`.

`port stats` shows cumulative byte, packet, and aggregate error counters by
default. Add `--rates`, `--traffic`, `--sizes`, or `--errors` for individual
groups, or `--full` for the complete statistics response. These flags only
filter presentation; the core API always returns the complete normalized model.

Run all local checks:

```bash
ruff format --check .
ruff check .
mypy
pytest
```

## Configuration

Configuration is resolved in this order, with later values overriding earlier
ones:

```text
built-in defaults
< TOML defaults
< selected TOML device
< .env in the current working directory
< process environment
< explicit CLI options
```

See [the configuration documentation](docs/configuration.md) and
[`config.example.toml`](config.example.toml).

## Device support

New firmware versions never become supported implicitly. Each exact model and
firmware combination must be tested, registered in the relevant device plugin,
and released. See [the device plugin documentation](docs/device-plugins.md).

Currently supported:

| Device | Product code | Firmware | Build | Operations |
| --- | --- | --- | --- | --- |
| RB260GS | `CSS106-5G-1S` | `2.19` | `0x6a181cd5` | Complete local reads; guarded port, name, and SNMP metadata writes |

The supported read surface includes system, management, health, port
configuration/state, complete statistics, SFP diagnostics, forwarding, port
lock, mirroring, bandwidth limits, VLANs, hosts, RSTP, SNMP, learned IGMP
groups, and ACL rules. See the
[CSS106 2.19 read-coverage matrix](docs/css106-2.19-read-coverage.md).
Device/port-name, port-configuration, and SNMP contact/location writes use
read-before-write, skip no-op POSTs, and verify the complete relevant writable
state after the change. Port writes are limited to Ethernet ports 1-5; port 6
is reserved for SFP management and is never modified. SNMP writes preserve the
raw enabled and community fields read from the device.

## License

[MIT](LICENSE)
