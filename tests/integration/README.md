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

The CSS106 write tests change and restore the device name, SNMP metadata, and a
port name in `finally`. The port test uses port 1 by default; select another
port with `SWOS_INTEGRATION_WRITE_PORT`.
