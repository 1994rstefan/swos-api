# Configuration

The CLI supports TOML profiles, `.env` files, process environment variables,
and direct options.

## Precedence

Later sources override earlier sources:

```text
built-in defaults
< TOML defaults
< selected TOML device
< .env in the current working directory
< process environment
< explicit CLI options
```

An existing process environment variable always overrides the equivalent value
from `.env`.

## Bootstrap settings

The configuration path is resolved from `--config`, `SWOS_CONFIG`, and finally
the platform default. Relative paths are resolved against the current working
directory. The selected profile is resolved from `--device`, `SWOS_DEVICE`, and
then `[defaults].device`.

If a device name is selected, that exact profile must exist under `[devices]`.
Direct connection overrides modify a selected profile; they do not create an
implicit profile.

## Setting names

| TOML | Environment | CLI |
| --- | --- | --- |
| `device` | `SWOS_DEVICE` | `--device` |
| `output` | `SWOS_OUTPUT` | `--output`, `-o` |
| `url` | `SWOS_URL` | `--url` |
| `username` | `SWOS_USERNAME` | `--username` |
| `password` | `SWOS_PASSWORD` | `--password` |
| `model` | `SWOS_MODEL` | `--model` |
| `firmware` | `SWOS_FIRMWARE` | `--firmware` |
| `timeout` | `SWOS_TIMEOUT` | `--timeout` |
| `verify_tls` | `SWOS_VERIFY_TLS` | `--verify-tls`, `--no-verify-tls` |

`SWOS_CONFIG` and `--config` are bootstrap controls and are not keys inside the
selected TOML file.

Passwords should normally be supplied through `SWOS_PASSWORD`; command-line
passwords may be visible in process listings. A future keyring integration is
planned. Secret values are excluded from configuration validation errors.

Administrator password rotation does not accept the new password through a
plain command-line value or the persistent settings above. Use exactly one of
`swosctl system password set --new-password-env NAME` or
`swosctl system password set --new-password-stdin`. Both preserve an empty
password; stdin removes one trailing LF or CRLF delimiter.

## Output

- `human` provides terminal-oriented output.
- `json` emits one compact JSON document.
- `json-pretty` emits the same data and schema with indentation.

Machine-readable success responses use:

```json
{"ok":true,"data":{}}
```

Machine-readable errors use:

```json
{"ok":false,"error":{"code":"error_code","message":"Description"}}
```

This also applies to argument parser and configuration errors whenever a JSON
mode was selected through CLI options, process environment, or `.env`.
