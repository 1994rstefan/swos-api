# Device plugins

Device support is delivered as independently installable Python distributions.
Plugins register under the `swos.devices` entry-point group.

```toml
[project.entry-points."swos.devices"]
css106 = "swos_device_css106.plugin:plugin"
```

Each plugin declares exact support records containing firmware family, product
code, firmware version, and optionally build ID. No firmware range silently
grants support to a new release.

Firmware identifiers are compared as exact strings. They are deliberately not
normalized as Python package versions: `2.19`, `2.19.0`, and `v2.19` are three
different support identifiers until each observed value is explicitly tested.

## Untested firmware

By default, only identity probing is permitted on an unknown firmware version.
Normal reads and writes are rejected.

The global CLI safety overrides are:

- `--allow-untested-firmware` for read operations
- `--allow-untested-firmware-writes` for writes, also implying read permission

Commands that use an override include a machine-readable warning in JSON output
and a `Warning:` line in human output.

The write override must be explicit for an invocation. It is enforced in
`swos-core`, so CLI and future Ansible consumers have identical safeguards.

## Testing requirements

A support record requires protocol fixtures, contract tests, regression tests,
and safe hardware validation where hardware is available. Model capabilities
must be tested independently even when multiple products share a firmware
image.

The current `swos-device-css106` package supports read-only system information,
port state, cumulative counters, per-port VLAN policy, and configured VLAN
table entries, plus static and dynamically learned hosts for RB260GS
and RSTP bridge/port state for RB260GS (`CSS106-5G-1S`) running SwOS `2.19`,
build `0x6a181cd5`. RB260GSP is recognized as a separate product but remains
unsupported.
