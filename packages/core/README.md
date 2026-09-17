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

Desired state covers device names, port names, SNMP contact/location metadata,
complete static-host tables, and complete ordered ACL tables. Static-host writes
reuse `HostEntry` but reject dynamic entries. `None` preserves an omitted SNMP
metadata field, while an empty string explicitly clears it.

Whole-table replacement requires an `expected_current` baseline. The adapter
compares that baseline with its fresh read and aborts stale mutations before a
POST. Device plugins advertise static-host and ACL write capabilities
independently.

Network link speeds and rates use bits per second in public models and JSON
representations.
