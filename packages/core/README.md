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
Matching `validate_*` methods enforce the same firmware policy, capability, and
adapter-specific preconditions without performing a write. Consumers use these
after fresh reads to implement device-validating dry runs and check mode.

Desired state covers administrator password rotation, complete system
configuration, device names, port names, per-port RSTP enable, bridge settings,
forwarding matrix/mirroring/port policy, per-port VLAN policy, SNMP
contact/location metadata, complete VLAN/static-host tables, and complete ordered
ACL tables. `PasswordUpdate` stores its value as `SecretStr` and excludes it from
all model serialization.
Static-host writes reuse `HostEntry` but reject dynamic entries. `None` preserves
an omitted field where supported; explicit `"unlimited"` clears an egress rate.

Whole-table replacement plus RSTP and forwarding mutation requires an
`expected_current` baseline. The adapter compares that baseline with its fresh
read and aborts stale mutations before a POST. Device plugins advertise safe
per-port and higher-risk global write capabilities independently.

`SystemConfigurationUpdate` is sparse, but its adapter operation requires a
full `SystemInfo` baseline and writes a complete preserved device object.
Clearable address/MAC/VLAN values use the explicit `"unset"` value; `None`
always means preserve. Adapter operation warnings are retained alongside any
firmware-policy warning in the public `OperationResult`.

Network link speeds and rates use bits per second in public models and JSON
representations.
