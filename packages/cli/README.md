# swos-cli

Command-line interface built on the public `swos-core` API.

Read commands cover system, ports, complete statistics, SFP, forwarding, host
tables, RSTP, SNMP, VLANs, learned IGMP groups, and ACL rules. Human, compact
JSON, and pretty JSON output are supported. `port stats` provides concise output
by default and adds `--rates`, `--traffic`, `--sizes`, `--errors`, or `--full`
groups on request.

`port list` reports configured negotiation as `"auto"` or as an object with
`speed_bps` and `duplex`. Operational `speed_bps` and `full_duplex` remain
separate fields describing the current link. All JSON link speeds use bits per
second; human output selects an appropriate Mbps or Gbps unit.

Guarded write commands are:

```bash
swosctl system rename "Office Switch" --device office
swosctl system configure --static-ip 192.0.2.10 --device office
swosctl system configure --igmp-snooping on --igmp-version v3 --device office
swosctl system configure --allow-port 1 --allow-port 6 --device office
swosctl port rename 1 Uplink --device office
swosctl port configure 5 --state enabled --flow-control on --device office
swosctl port configure 5 --negotiation auto --device office
swosctl port configure 5 --negotiation forced --speed-bps 100000000 --duplex full --device office
swosctl snmp metadata set --contact "Network Operations" --device office
swosctl snmp metadata set --location "" --device office
swosctl host add --mac 02:00:00:00:00:05 --vlan 10 --port 5 --device office
swosctl host remove --mac 02:00:00:00:00:05 --vlan 10 --device office
swosctl rstp configure 5 --state disabled --device office
swosctl forwarding configure 5 --lock on --device office
swosctl forwarding configure 5 --lock-on-first off --egress-rate-bps 1000000 --device office
swosctl forwarding configure 5 --egress-unlimited --device office
swosctl vlan configure-port 5 --egress strip --device office
swosctl vlan set 10 --igmp-snooping on --port-mode 5=strip --device office
swosctl vlan remove 10 --device office
swosctl -o json port rename 1 Uplink --device office
```

Omitted SNMP metadata options preserve their current values. Passing an empty
string explicitly clears the selected field. Write commands do not prompt for
confirmation; firmware write authorization is enforced by `swos-core`.

`system configure` accepts explicit options for address mode/static IP, admin
MAC, identity, management source/prefix/ports/VLAN, independent VLAN lookup,
IGMP snooping/querier/fast-leave/version, and discovery-protocol ports. Repeated
port options describe the complete desired mask. Use `--unset-static-ip`,
`--unset-admin-mac`, `--unset-allow-from`, or `--unset-allow-vlan` for wire-zero
values, and the `--clear-*-ports` flags for empty non-management masks. The
command reads and passes a complete `SystemInfo` baseline before writing.

CSS106 currently rejects address-mode changes, active static-IP changes,
DHCP-only static-IP staging, and management VLAN changes. A static IP may be
staged only while DHCP with fallback remains active. Every management
allowed-port mask must include port 6, and no system mask may change port 6's
existing bit.

Admin MAC, allow-from network, and allowed-port changes are explicitly
authorized lockout-capable operations. Their successful result contains a
`management_lockout_risk` warning with before/after values. The client attempts
same-URL readback, but cannot prove caller reachability and does not treat the
device's operational IP as the caller source. If connectivity is lost, the
write outcome is uncertain and recovery may require a manual factory reset.

RSTP and forwarding configuration commands are direct, non-interactive
read/plan/write operations. They pass the initial read as a precondition, so an
intervening configuration change aborts before POST. Only ports 1-5 are accepted.
The CSS106 profile advertises RSTP enable plus lock, lock-on-first, and egress
rate; bridge-global, matrix, and mirroring mutation remains unavailable.

`vlan configure-port` accepts only ports 1-5 and passes the complete initial
per-port policy as its write precondition. `vlan set` and `vlan remove` plan a
full-table replacement without exposing port 6 as an option. CSS106 keeps the
`vlan_table_write` capability disabled pending hardware validation, so those
table commands currently fail closed before adapter dispatch on that profile.

Static-host add updates the exact MAC/VLAN key in place and accepts repeatable
`--port` options restricted to ports 1-5. CLI table mutations pass their read
baseline to the adapter and abort if its fresh read differs. Every successful
table mutation returns the complete verified table in JSON output.

Typed `acl add` and numbered `acl remove` commands are implemented, including
repeatable `--ingress-port` and `--redirect-port` options. ACL ingress cannot
include management port 6. These commands require an `acl_write` capability;
CSS106 does not currently advertise it pending harmless hardware validation.

Port configuration writes accept only Ethernet ports 1-5. Port 6 is the SFP
management path and cannot be renamed or configured. Forced negotiation requires
both `--speed-bps` (exactly `10000000` or `100000000`) and `--duplex`; auto
negotiation preserves the dormant forced speed and duplex. Omitted options
preserve their current values, and an update with no options is rejected.
