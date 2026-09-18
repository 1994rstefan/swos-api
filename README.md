# swos-api

An independent, device-agnostic Python API for managing MikroTik SwOS devices.

> [!WARNING]
> The project is in pre-alpha development. Device support is deliberately
> limited to exact hardware and firmware combinations listed below.

## Architecture

This monorepo contains independently versioned Python distributions:

- `swos-core`: public API, transport, plugin contracts, and firmware safeguards
- `swos-cli`: command-line client built exclusively on `swos-core`
- `swos-ansible`: installable `swos.api` collection built exclusively on `swos-core`
- `swos-device-css106`: CSS106 device support

The CLI and Ansible integration never contain device-specific HTTP logic.
Device packages are discovered through Python entry points and declare the exact
model and firmware combinations they support.

See [the architecture documentation](docs/architecture.md) for details.

## Ansible

`swos-ansible` 0.1.0 installs the `swos.api` collection into Python's
`ansible_collections` namespace. It provides normalized facts and idempotent,
check-mode-safe modules for hardware-enabled non-credential writes. Password
rotation is intentionally not exposed through Ansible yet.

```yaml
- name: Gather switch facts
  swos.api.facts:
    url: http://192.0.2.10
    password: "{{ vault_swos_password }}"
  delegate_to: localhost

- name: Configure port 5 VLAN policy
  swos.api.vlan_port_policy:
    url: http://192.0.2.10
    password: "{{ vault_swos_password }}"
    port: 5
    mode: strict
    receive: untagged_only
    default_vlan_id: 10
    force_vlan_id: true
    egress: strip
  delegate_to: localhost
```

See [the Ansible integration documentation](docs/ansible.md) for installation,
module inventory, safety flags, and result behavior.

## Development setup

Python 3.11 through 3.14 and [uv](https://docs.astral.sh/uv/) 0.12.16 are
supported for development. The committed universal lock file covers the whole
workspace and the development tools.

```bash
uv sync --locked --all-packages
```

Workspace packages are installed editable. Published dependency declarations
remain in each distribution's `pyproject.toml`; local `swos-core` dependencies
resolve from the workspace during development.

Run the initial CLI:

```bash
swosctl --version
swosctl -o json --version
swosctl -o json-pretty --version
swosctl --device office system show
swosctl system show --device office
swosctl system rename "Office Switch" --device office
swosctl system configure --static-ip 192.0.2.10 --device office
swosctl system configure --address-mode static --static-ip 192.0.2.20 --device office
swosctl system configure --address-mode dhcp_with_fallback --readback-url http://192.0.2.10 --device office
swosctl system configure --igmp-snooping on --igmp-version v3 --device office
swosctl system password set --new-password-env NEW_SWOS_PASSWORD --device office
swosctl port list --device office
swosctl port rename 1 Uplink --device office
swosctl port configure 5 --flow-control on --device office
swosctl port configure 5 --negotiation forced --speed-bps 100000000 --duplex full --device office
swosctl port stats --device office
swosctl port stats --full --device office
swosctl sfp show --device office
swosctl forwarding show --device office
swosctl forwarding configure 5 --lock on --device office
swosctl forwarding configure 5 --lock-on-first off --egress-unlimited --device office
swosctl host list --device office
swosctl host add --mac 02:00:00:00:00:05 --vlan 10 --port 5 --device office
swosctl host remove --mac 02:00:00:00:00:05 --vlan 10 --device office
swosctl igmp list --device office
swosctl acl list --device office
swosctl rstp show --device office
swosctl rstp configure 5 --state enabled --device office
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
uv lock --check
uv sync --locked --all-packages
uv run --no-sync ruff format --check .
uv run --no-sync ruff check .
uv run --no-sync mypy
uv run --no-sync pytest
uv build --all-packages --out-dir dist
uv run --no-sync twine check dist/*
uv run --no-sync --directory packages/ansible/src/ansible_collections/swos/api ansible-test sanity --python 3.11
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
| RB260GS | `CSS106-5G-1S` | `2.19` | `0x6a181cd5` | Complete local reads; guarded password, system, port, per-port VLAN, RSTP enable, forwarding policy, name, SNMP metadata, and static-host writes |

The supported read surface includes system, management, health, port
configuration/state, complete statistics, SFP diagnostics, forwarding, port
lock, mirroring, bandwidth limits, VLANs, hosts, RSTP, SNMP, learned IGMP
groups, and ACL rules. See the
[CSS106 2.19 read-coverage matrix](docs/css106-2.19-read-coverage.md).
Device/port-name, port-configuration, SNMP contact/location, and static-host
table writes use read-before-write, skip no-op POSTs, and verify the complete
relevant writable state after the change. Static-host mutations also require the
fresh adapter state to match the caller's expected baseline. Static-host targets
are limited to Ethernet ports 1-5; port 6 is reserved for SFP management. SNMP
writes preserve the raw enabled and community fields read from the device.

Per-port RSTP enable and forwarding lock, lock-on-first, and egress-rate writes
are exposed for ports 1-5. They require the adapter's fresh configuration to
match the CLI baseline, preserve the complete endpoint group, skip no-ops, and
verify complete-group readback. Port 6's RSTP bit, forwarding row, and every
destination relationship involving port 6 are immutable. Port 6 cannot be a
mirror source or target. Bridge-global, forwarding-matrix, and mirroring writes
remain capability-disabled pending dedicated hardware validation.

Per-port VLAN policy writes cover `vlan`, `vlni`, `dvid`, `fvid`, and `vlnh`
for Ethernet ports 1-5. They require an exact expected baseline, preserve all
five policy values for management port 6, skip no-ops, and verify complete-group
readback. Guarded whole-table `/vlan.b` replacement is implemented with the same
identity, baseline, no-op, and full readback checks. Every desired table must
preserve port 6 membership for every VLAN ID. The `vlan_table_write` capability
remains disabled pending dedicated hardware validation.

Guarded ACL replacement and typed CLI mutation commands are implemented, but
the exact CSS106 profile does not advertise `acl_write`. ACL writes remain
disabled until a no-effect rule can be validated and restored on hardware.

## License

[MIT](LICENSE)
