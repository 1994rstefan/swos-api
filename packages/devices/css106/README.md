# swos-device-css106

Device support for the MikroTik CSS106 firmware family.

The current release supports the complete practical local read-only web-UI
surface for RB260GS (`CSS106-5G-1S`) running SwOS `2.19`, build `0x6a181cd5`.
This includes system, management, health, port configuration/state, complete
statistics, SFP diagnostics, forwarding, port lock, mirroring, bandwidth
limits, VLANs, hosts, RSTP, SNMP, learned IGMP groups, and ACL rules. RB260GSP
is detected but remains unsupported until separately validated on hardware.

CSS106 reports system uptime in 100 Hz ticks. The adapter normalizes this value
to whole seconds in the device-independent `SystemInfo` model.

VLAN reads use `/fwd.b` for per-port policy and `/vlan.b` for explicit table
entries. The table fixture includes synthetic entries because the validated
device currently has an empty VLAN table.

Host-table reads combine configured entries from `/host.b` with dynamically
learned entries from `/!dhost.b`. Protocol fixtures use synthetic locally
administered MAC addresses rather than addresses observed on hardware.

ACL and learned IGMP tables were empty on the validated device, and no SFP
module was installed. Their endpoint availability and empty response behavior
are hardware-validated; populated decoding is covered by UI-derived sanitized
fixtures. See the repository's `docs/css106-2.19-read-coverage.md` for the exact
field-level matrix and remaining validation limits.
