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

The CSS106 write tests change and restore the device name, SNMP metadata, port
name, and flow-control state in `finally`. Port tests run only after confirming
that their target is link-down. The name test uses Ethernet port 5 by default;
select another Ethernet port (1-5 only) with `SWOS_INTEGRATION_WRITE_PORT`.
The configuration test always targets down port 5 and toggles only flow control.
Port 6 is the SFP management path and is always rejected. The hardware test
never disables a port or changes negotiation.
