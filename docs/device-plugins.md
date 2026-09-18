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
`swos-core`, so CLI and Ansible consumers have identical safeguards. Ansible
configuration modules resolve write policy before their initial read, including
in check mode.

## Testing requirements

A support record requires protocol fixtures, contract tests, regression tests,
and safe hardware validation where hardware is available. Model capabilities
must be tested independently even when multiple products share a firmware
image.

The current `swos-device-css106` package supports the complete practical local
read-only web-UI surface for RB260GS (`CSS106-5G-1S`) running SwOS `2.19`, build
`0x6a181cd5`: system, management, health, port configuration/state, complete
statistics, SFP diagnostics, forwarding, port lock, mirroring, bandwidth
limits, VLANs, hosts, RSTP, SNMP, learned IGMP groups, and ACL rules.
Guarded, idempotent device-name, port-name, complete SNMP, per-port RSTP
enable, per-port forwarding lock/lock-on-first/egress-rate, and per-port VLAN
policy writes are also supported for this exact hardware, firmware, and build
combination. Distinct capabilities are independently advertised only for
RB260GS. Bridge-global, forwarding-matrix, mirroring, whole VLAN table, and ACL
writes are safety-bounded and retain separately gated representative hardware
tests; capability exposure does not imply exhaustive hardware validation.

The exact field-level matrix, endpoint inventory, scaling rules, fixture status,
and hardware-validation limits are documented in
[`css106-2.19-read-coverage.md`](css106-2.19-read-coverage.md). RB260GSP is
recognized as a separate product but remains unsupported.
