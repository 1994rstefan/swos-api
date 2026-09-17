# swos-core

Device-independent API, transport primitives, plugin contracts, and safety
policies for the `swos-api` project.

The policy-bound `SwOSDevice` read API exposes system and management data,
ports, complete traffic statistics, SFP diagnostics, forwarding policy, hosts,
RSTP, SNMP, VLANs, learned IGMP groups, and ACL rules. Concrete plugins return
validated device-independent models and keep endpoint/wire details outside this
package.
