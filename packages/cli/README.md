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
swosctl -o json port rename 1 Uplink --device office
```

Omitted SNMP metadata options preserve their current values. Passing an empty
string explicitly clears the selected field. Write commands do not prompt for
confirmation; firmware write authorization is enforced by `swos-core`.

Port configuration writes accept only Ethernet ports 1-5. Port 6 is the SFP
management path and cannot be renamed or configured. Forced negotiation requires
both `--speed-bps` (exactly `10000000` or `100000000`) and `--duplex`; auto
negotiation preserves the dormant forced speed and duplex. Omitted options
preserve their current values, and an update with no options is rejected.
