# Ansible integration

`swos-ansible` 0.1.0 is an independently buildable Python distribution that
installs the `swos.api` Ansible collection. It depends on `swos-core`, but not on
a concrete device package or `ansible-core`. Install `ansible-core`,
`swos-ansible`, and the required `swos-device-*` plugin into the same
controller-side Python environment.

```bash
python -m pip install ansible-core swos-ansible swos-device-css106
ansible-doc swos.api.facts
```

The collection is intended to run in a local play or with
`delegate_to: localhost`; no code is installed on the switch. It discovers
device support through the standard `swos.devices` Python entry-point group and
never imports a device adapter or issues direct HTTP requests.

## Modules

| FQCN | Purpose |
| --- | --- |
| `swos.api.facts` | Gather selected normalized read groups as `ansible_facts.swos` |
| `swos.api.device_name` | Set or clear the device name |
| `swos.api.port_name` | Set or clear an Ethernet port 1-5 name |
| `swos.api.port_configuration` | Manage enabled, negotiation, speed/duplex, and flow control on ports 1-5 |
| `swos.api.snmp_metadata` | Manage SNMP contact and location while preserving service/community fields |
| `swos.api.static_hosts` | Declare the complete ordered static-host table for ports 1-5 |
| `swos.api.rstp_port` | Manage per-port RSTP enable state on ports 1-5 |
| `swos.api.forwarding_port_policy` | Manage lock, lock-on-first, and egress rate on ports 1-5 |
| `swos.api.vlan_port_policy` | Manage mode, receive, default/forced VLAN ID, and egress policy on ports 1-5 |

Static hosts are declarative: `hosts` is the complete desired static table and
an empty list removes every static entry. Dynamically learned entries are
excluded from both the desired table and the optimistic-concurrency baseline.
The table is limited to 2048 entries. Device and port names are printable ASCII
up to 16 characters; SNMP contact and location are printable ASCII up to 64
characters.

## Connection and safety

Every module accepts `url`, `username`, `password`, `timeout`, and
`validate_certs`. Password arguments are marked `no_log` in Ansible. Device
model and firmware are detected by installed plugins rather than selected by a
module option.

Exact support records remain authoritative. The policy flags intentionally use
the same names and semantics as `FirmwareSafetyPolicy`:

- `allow_untested_firmware` permits facts/read operations on unknown firmware.
- `allow_untested_firmware_writes` permits configuration operations and their
  prerequisite reads on unknown firmware.

Configuration modules pre-authorize write policy before reading current state.
This also happens in check mode, so a check cannot imply that an unsafe real run
would succeed. Overrides produce human-readable `warnings` and structured
`swos_warnings` entries containing `code` and `message`.

## Idempotence and check mode

Every configuration module reads normalized current state and computes a
desired projection. It reports `changed: false` and does not call a write method
when current state already matches. In check mode it returns projected state but
never calls a core write method. Public `SwOSDevice.validate_*` methods enforce
the selected plugin's writable-port, table, active-link, and metadata constraints
against the freshly read state without issuing a POST.

RSTP, forwarding, static-host, and VLAN modules pass the same fresh read to the
core API as the expected baseline for guarded writes. The plugin remains
responsible for preserving immutable endpoint fields, performing verified
readback, and rejecting concurrent state changes.

Failures raised after Ansible has parsed module arguments use Ansible's normal
failed result with `msg` plus an `error` object containing stable `type` and
`message` fields. Parser failures are emitted directly by `AnsibleModule` and
therefore do not include the collection's `error` object. Core domain and
firmware errors remain machine-readable without leaking connection secrets.
