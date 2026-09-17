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

Network link speeds and rates use bits per second in public models and JSON
representations.
