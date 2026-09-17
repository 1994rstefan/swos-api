# swos-core

Device-independent API, transport primitives, plugin contracts, and safety
policies for the `swos-api` project.

The policy-bound `SwOSDevice` read API exposes system and management data,
ports, complete traffic statistics, SFP diagnostics, forwarding policy, hosts,
RSTP, SNMP, VLANs, learned IGMP groups, and ACL rules. Concrete plugins return
validated device-independent models and keep endpoint/wire details outside this
package.

Guarded writes use typed desired-state models and return an `OperationResult`
containing the verified state, whether a change was required, and any
operation-specific firmware warning. `SwOSDevice` enforces write authorization
and a distinct write capability before dispatching to a plugin.

Desired state covers device names, port names, per-port RSTP enable, bridge
settings, forwarding matrix/mirroring/port policy, per-port VLAN policy, SNMP
contact/location metadata, complete VLAN/static-host tables, and complete
ordered ACL tables.
Static-host writes reuse `HostEntry` but reject dynamic entries. `None` preserves
an omitted field where supported; explicit `"unlimited"` clears an egress rate.

Whole-table replacement plus RSTP and forwarding mutation requires an
`expected_current` baseline. The adapter compares that baseline with its fresh
read and aborts stale mutations before a POST. Device plugins advertise safe
per-port and higher-risk global write capabilities independently.

Network link speeds and rates use bits per second in public models and JSON
representations.
