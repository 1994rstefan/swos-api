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
swosctl port list --device office
swosctl port stats --device office
```

Global options may be placed before, between, or after command names. The two
`system show` forms above are equivalent.

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
| RB260GS | `CSS106-5G-1S` | `2.19` | `0x6a181cd5` | Read system, port state, and counters |

## License

[MIT](LICENSE)
