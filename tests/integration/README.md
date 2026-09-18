# Hardware integration tests

Hardware tests will live here and remain opt-in. Read-only and destructive
tests must use separate pytest markers, capture the exact model and firmware,
and preserve the active management path.

Read-only integration tests require:

```bash
pytest --run-integration -m integration
```

The CSS106 test defaults to `http://192.168.88.1` with user `admin` and an
empty password. Override these values with `SWOS_INTEGRATION_URL`,
`SWOS_INTEGRATION_USERNAME`, and `SWOS_INTEGRATION_PASSWORD`.

Destructive tests require both explicit gates:

```bash
pytest --run-integration --run-destructive -m destructive
```

Administrator password rotation has a third, separate gate and must be selected
explicitly:

```bash
pytest --run-integration --run-destructive --run-password-rotation -m password_rotation
```

The password test reads the original credential from the configured
`DeviceConnection` secret, rotates to a fixed 15-character printable ASCII
temporary credential, verifies the same facade with that credential, and
rotates back. It skips when the configured password exceeds 15 JavaScript
UTF-16 code units or already equals the temporary credential. Cleanup probes
the original credential first without writing. Only when the original probe
fails and the temporary credential succeeds for the exact expected device does
cleanup attempt restoration; if neither credential works, the test stops
writing and reports that a manual reset is required without printing either
credential.

Management address and VLAN reconnect tests have their own third gate:

```bash
pytest --run-integration --run-destructive --run-management-reconnect -m management_reconnect
```

The VLAN test additionally requires `SWOS_INTEGRATION_MANAGEMENT_PORT=6`. It sets
management VLAN from unset to 1 only when port 6 has PVID 1, accepts untagged
frames, has port-policy egress set to strip tags, and has an explicit VLAN 1
table membership whose effective egress also strips tags. Empty tables and
preserve egress therefore skip safely. The test only reads port 6 and never
changes its policy or membership. The address-mode test changes
DHCP-with-fallback to static at the same address and restores it.

The optional actual address move requires `SWOS_INTEGRATION_TEMPORARY_IP` and an
acknowledgement whose value is that same address, for example
`SWOS_INTEGRATION_TEMPORARY_IP_ACKNOWLEDGED=192.168.88.2`. It is skipped when
either is absent or when an unauthenticated TCP connection shows that the target
address is occupied. No HTTP credentials are sent during the vacancy check.
Cleanup probes both original and temporary URLs, gathers every observation, and
restores only when every reachable observation is the exact expected temporary
device state. Any unknown/conflicting observation refuses all writes. If neither
URL is reachable, cleanup raises the reset-required domain error and performs no
further write.

The CSS106 write tests change and restore the device name, SNMP metadata, port
name, flow-control state, RSTP enable, lock, lock-on-first, egress rate, and
selected system masks in `finally`. The system-mask tests toggle only port 5 in
the discovery, IGMP fast-leave, or management allowed-port mask, one mask per
test. They preserve port 6's exact mask state; management allowed-port tests
also require and retain port 6 and assert the lockout-risk operation warning.
The fast-leave test runs only while global IGMP snooping is enabled. The
per-port VLAN test changes only port 5's egress-header policy. Both kinds of
test precompute their exact temporary configuration before POST. Cleanup
fresh-reads the full writable configuration: it restores only from that
temporary state, does nothing if already at the original state, and refuses to
overwrite any third state. Port tests run only after confirming that their
target is link-down.
Each test changes one setting at a time. The name test uses Ethernet port 5 by default;
select another Ethernet port (1-5 only) with `SWOS_INTEGRATION_WRITE_PORT`.
The configuration, RSTP, and forwarding tests always target down port 5. Port 6
is the SFP management path and is always rejected. The hardware tests never
disable an Ethernet port, change negotiation, alter forwarding destinations, or
configure mirroring.
The VLAN table is never changed by hardware tests, and every VLAN policy test
asserts that the SFP port-6 policy remains identical. System tests do not change
address mode, static IP, management VLAN, allow-from policy, or admin MAC unless
the separately gated management reconnect marker is selected.

Static-host, RSTP, forwarding, VLAN-policy, and system-mask cleanup passes the
verified post-mutation state as the restore precondition. A concurrent
configuration change therefore aborts the `finally` cleanup rather than being
accepted as a new baseline and overwritten.
