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
swosctl -o json port rename 1 Uplink --device office
```

Omitted SNMP metadata options preserve their current values. Passing an empty
string explicitly clears the selected field. Write commands do not prompt for
confirmation; firmware write authorization is enforced by `swos-core`.

RSTP and forwarding configuration commands are direct, non-interactive
read/plan/write operations. They pass the initial read as a precondition, so an
intervening configuration change aborts before POST. Only ports 1-5 are accepted.
The CSS106 profile advertises RSTP enable plus lock, lock-on-first, and egress
rate; bridge-global, matrix, and mirroring mutation remains unavailable.

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
