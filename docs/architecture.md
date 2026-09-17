# Architecture

`swos-api` separates device-independent consumers from firmware-specific wire
protocols.

```text
swos-cli -----------------> swos-core
                               ^
                               |
swos-device-css106 ------------+

swos-ansible --------------> swos-core       (planned)
```

## Package boundaries

`swos-core` owns public domain models, the device protocol, HTTP transport,
plugin discovery, errors, and firmware safety policy. It must not contain raw
CSS106 field names or endpoint mappings.

Raw plugin adapters are not returned to consumers. `swos-core` wraps them in a
policy-bound `SwOSDevice` facade that checks firmware support immediately before
each exposed operation. Write methods enforce write policy and a distinct write
capability in this facade rather than relying on CLI checks.

`swos-cli` owns argument parsing, layered user configuration, output rendering,
and process exit behavior. It performs no direct HTTP requests.

Device support distributions own product aliases, exact support declarations,
capabilities, firmware profiles, protocol encoding, and protocol fixtures.

## Identity

A device identity retains multiple identifiers:

- marketing name, such as `RB260GS`
- product code, such as `CSS106-5G-1S`
- firmware image family, such as `css106`
- SwOS version, such as `2.19`
- optional firmware build identifier

Adapters are matched using the firmware family, product code, exact firmware
version, and an optional build identifier. Marketing names are aliases, not the
canonical matching key.

## CSS106 family

MikroTik documents RB260GS (`CSS106-5G-1S`) and RB260GSP
(`CSS106-1G-4P-1S`) as separate products in the same CSS106 family. They use
the same QCA8337 switch chip and firmware image, while RB260GSP adds passive
PoE output on ports 2-5.

They therefore belong in one `swos-device-css106` distribution with separate
model profiles. Support remains independent per product code and firmware:
testing RB260GS does not implicitly support RB260GSP.

## Release boundaries

Core and CLI follow independent semantic versions. Device plugin versions
follow the newest supported firmware family release, with PEP 440 post releases
for plugin-only corrections. The explicit support matrix remains authoritative.
