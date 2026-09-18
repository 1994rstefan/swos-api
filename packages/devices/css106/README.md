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
`spdc`, `dpxc`, and `fct`, preserving every unrelated value. Device-name writes
use the complete system object described below. The complete SNMP body is
ordered `en`, `com`, `ci`, `loc` and preserves the raw enabled and community
fields.

Guarded complete `/sys.b` configuration writes post exactly `iptp`, `sip`,
`amac`, `id`, `alla`, `allm`, `allp`, `avln`, `ivl`, `igmp`, `igmq`, `igfl`,
`igve`, and `pdsc` in UI order. Read-only and unrelated fields are excluded.
The adapter requires a complete normalized `SystemInfo` baseline, rejects stale
state, preserves every omitted field, skips no-ops, and attempts complete-object
verification through same-URL readback. All three port masks preserve bit 5;
management allowed ports must include port 6.

Management VLAN changes fail closed until continuity is provable from VLAN and
port-policy state. Address-mode and active static-IP changes fail closed until a
reconnect workflow exists; a static address can be staged only in DHCP with
fallback, never in DHCP-only mode. Administrative MAC wire values are twelve
lowercase hex digits, text is hex encoded, IPv4 is little-endian, booleans are
`0`/`1`, and IGMP v2/v3 map to `0`/`1`. Numeric serialization matches the UI:
lowercase hexadecimal with the minimum even number of digits, including `0x00`
for zero. As in the UI's `Kb` transition, the complete desired wire state forces
the IGMP querier off whenever snooping is off.

Admin MAC, allow-from, and management allowed-port changes remain available as
explicitly authorized lockout writes. Successful operation results include a
`management_lockout_risk` warning with before/after values. Same-URL readback is
attempted but broader continuity cannot be proven: the device IP is not the
client source address, and connectivity loss leaves the write outcome uncertain
and may require a manual factory reset.

The profile also advertises guarded per-port RSTP enable and forwarding lock,
lock-on-first, and egress-rate writes for ports 1-5. CLI plans carry an expected
configuration; the adapter rechecks it from fresh `/sys.b` plus `/rstp.b` or
`/fwd.b` reads and rejects stale plans before POST. RSTP posts the complete
`ena` group. Forwarding posts `fp1` through `fp6`, `lck`, `lckf`, `imr`, `omr`,
`mrto`, and `or`, preserving every omitted value and verifying that complete
group after the write. Port 6's RSTP bit, `fp6`, and every destination
relationship involving port 6 cannot change. Port 6 is rejected as a mirror
source or target.

Guarded per-port VLAN policy writes are advertised for ports 1-5. They post the
complete ordered `/fwd.b` VLAN group `vlan`, `vlni`, `dvid`, `fvid`, `vlnh`
after exact identity and expected-baseline checks, preserve every port-6 value,
skip no-ops, and verify the complete group through readback.

Complete `/vlan.b` replacement validates and posts ordered `vid`, `ivl`, `igmp`,
`prt` rows. Every desired table must preserve management port 6's effective
membership for every VLAN ID versus the mandatory expected baseline. The
adapter rejects stale plans and verifies the complete table after POST. The
`vlan_table_write` capability is deliberately not advertised pending hardware
validation. Internal write-state parsing preserves wire row order, so readback
with reordered rows is rejected even though public `get_vlans()` output remains
sorted by VLAN ID.

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
