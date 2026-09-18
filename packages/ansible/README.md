# swos-ansible

`swos-ansible` is the installable `swos.api` Ansible collection for devices
supported by `swos-core` plugins. It contains no device-specific protocol or
HTTP code.

Install this distribution and at least one device plugin into the Python
environment used by the Ansible controller:

```bash
python -m pip install swos-ansible swos-device-css106
```

The wheel installs the collection under `ansible_collections/swos/api`, so its
modules are available by fully qualified collection name:

```yaml
- name: Gather normalized switch facts
  swos.api.facts:
    url: http://192.0.2.10
    password: "{{ vault_swos_password }}"
  register: switch
  delegate_to: localhost

- name: Configure the office uplink
  swos.api.port_configuration:
    url: http://192.0.2.10
    password: "{{ vault_swos_password }}"
    port: 1
    enabled: true
    negotiation: auto
    flow_control: true
  delegate_to: localhost
```

Modules use the controller's Python environment. Run them in a local play or
use `delegate_to: localhost` as above; no code is installed on the switch.

Every configuration module supports check mode and reports `changed` from a
fresh normalized read. Grouped writes use that same read as the core API's
optimistic-concurrency baseline. Exact firmware policy is enforced for both
normal and check-mode runs. Unknown firmware requires
`allow_untested_firmware` for facts and
`allow_untested_firmware_writes` for configuration modules; the latter also
permits prerequisite reads.

Common connection options are `url`, `username`, `password`, `timeout`, and
`validate_certs`. Results expose machine-readable core warnings as
`swos_warnings` and Ansible warning strings as `warnings`.

Available modules:

- `swos.api.facts`
- `swos.api.device_name`
- `swos.api.port_name`
- `swos.api.port_configuration`
- `swos.api.snmp_metadata`
- `swos.api.static_hosts`
- `swos.api.rstp_port`
- `swos.api.forwarding_port_policy`
- `swos.api.vlan_port_policy`

The Python execution layer is intentionally independent of `ansible-core`, so
it can be unit tested with a mocked public `SwOSDevice`.
