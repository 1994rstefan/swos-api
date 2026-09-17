# swos-device-css106

Device support for the MikroTik CSS106 firmware family.

The current release supports read-only system information, port state,
cumulative port counters, per-port VLAN policy, and configured VLAN table
entries, plus static and dynamically learned hosts for RB260GS
and RSTP bridge/port state for RB260GS (`CSS106-5G-1S`) running SwOS `2.19`,
build `0x6a181cd5`. RB260GSP is detected but remains unsupported until separately
validated on hardware.

CSS106 reports system uptime in 100 Hz ticks. The adapter normalizes this value
to whole seconds in the device-independent `SystemInfo` model.

VLAN reads use `/fwd.b` for per-port policy and `/vlan.b` for explicit table
entries. The table fixture includes synthetic entries because the validated
device currently has an empty VLAN table.

Host-table reads combine configured entries from `/host.b` with dynamically
learned entries from `/!dhost.b`. Protocol fixtures use synthetic locally
administered MAC addresses rather than addresses observed on hardware.
