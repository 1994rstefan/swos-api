# swos.api

This collection is distributed by the `swos-ansible` Python package and uses
only the public `swos-core` API. Install it with a device plugin in the Python
environment used by the Ansible controller:

```bash
python -m pip install swos-ansible swos-device-css106
```

Run modules in a local play or with `delegate_to: localhost`; they use the
controller's Python environment and install nothing on the switch.

All modules support check mode. Use `swos.api.facts` for normalized read data;
configuration modules cover device and port names, Ethernet port
configuration, SNMP metadata, static hosts, per-port RSTP and forwarding, and
per-port VLAN policy. Unknown firmware remains denied unless the explicit
`allow_untested_firmware` or `allow_untested_firmware_writes` policy flag is
set for that invocation.
