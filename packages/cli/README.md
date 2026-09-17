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

The first guarded write command is:

```bash
swosctl port rename 1 Uplink --device office
swosctl -o json port rename 1 Uplink --device office
```
