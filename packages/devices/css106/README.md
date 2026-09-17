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

Guarded device-name, port-name, Ethernet port-configuration, and SNMP
contact/location writes are supported on the exact RB260GS firmware/build listed
above. The adapter revalidates device identity, reads current state, skips no-op
changes, sends one `text/plain` POST, and verifies the full relevant writable
state through a fresh read. Device and port names are limited to 16 printable
ASCII characters; SNMP contact and location are limited to 64. Port writes are
restricted to ports 1-5 and never modify the port-6 SFP management path. Active
ports cannot be disabled or have negotiation changed. Auto negotiation preserves
the dormant forced speed/duplex fields; forced mode supports 10/100 Mbps and
full/half duplex. The complete `/link.b` body contains only `en`, `nm`, `an`,
`spdc`, `dpxc`, and `fct`, preserving every unrelated value. The sparse
device-name body contains only `id`. The complete SNMP body is ordered `en`,
`com`, `ci`, `loc` and preserves the raw enabled and community fields.

The profile also advertises guarded per-port RSTP enable and forwarding lock,
lock-on-first, and egress-rate writes for ports 1-5. CLI plans carry an expected
configuration; the adapter rechecks it from fresh `/sys.b` plus `/rstp.b` or
`/fwd.b` reads and rejects stale plans before POST. RSTP posts the complete
`ena` group. Forwarding posts `fp1` through `fp6`, `lck`, `lckf`, `imr`, `omr`,
`mrto`, and `or`, preserving every omitted value and verifying that complete
group after the write. Port 6's RSTP bit, `fp6`, and every destination
relationship involving port 6 cannot change. Port 6 is rejected as a mirror
source or target.

Bridge-global (`prio`, `cost`, `frmc`), forwarding-matrix, and mirroring
serialization use the same identity, baseline, no-op, complete-group, and
readback guards, but their independent capabilities remain disabled pending
hardware validation.

Complete static-host table replacement is also guarded on that exact device
identity. It validates row limits and the complete desired table before
transport, requires the fresh table to match the caller's expected baseline,
skips exact no-ops, sends one `text/plain` POST, and verifies every row through
a fresh read. `/host.b` rows are ordered `prt`, `adr`, `vid`, `drp`, `mir`; only
static entries targeting ports 1-5 are
accepted, with the table bounded by the 2048-entry forwarding database.

ACL replacement is implemented with the same baseline, serialization, and
readback guards. `/acl.b` rows preserve the firmware's complete 26-field order
and 32-rule limit. Rules are numbered consecutively and any rule whose ingress
includes management port 6 is rejected. Redirecting traffic to port 6 remains
representable. The plugin deliberately does not advertise `acl_write`: no
truly no-effect rule on a link-down port 5 has yet been proven and restored on
hardware.

SwOS does not expose a revision token or compare-and-swap operation. Table
writes detect changes between the CLI read and the adapter's fresh read, but
concurrent web-UI or API edits remain unsafe between that read and POST.
`/link.b`, `/snmp.b`, `/rstp.b`, and `/fwd.b` require complete writable-group
POSTs.
