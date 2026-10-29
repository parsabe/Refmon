# Event vocabulary

Phase 0 fixes the shape of events. Phase 1 pins down which attributes the Judge reads.

## Forms

- `RawEvent` (sensor to Observe): may carry `object.content` and free-text attribute values such as `domain`. Memory, lab fixtures and isolated-lab recordings with synthetic users only; harmless synthetic content only.
- `Event` (Observe output): `object.fingerprint` only (`hmac:` plus 16 to 64 hex digits). `attrs` keys must be on the allowlist below; any other key is rejected. Values are numbers, flags, or identifiers matching `[A-Za-z0-9_.:@-]{1,64}`.

## Event types

Defined in CLAUDE.md C2: `content_in`, `request_in`, `exec`, `net_connect`, `file_write`, `persist`, `asset_access`, `priv_change`, `security_tamper`, `user_input`, `admin_input`, `request_end`, `response_out`.

## Conventions

- `exec`: `actor` is the process that spawns. The spawned process appears in later events with `actor.parent` set to the spawner.
- `request_end`: same request fingerprint as the `request_in` it closes; ends the period in which the handling process carries the request label.
- `response_out`: size only (`bytes`), never content.

## Allowed `Event` attribute keys

Source of truth: CLAUDE.md C2 and `EVENT_ATTR_KEYS` in `src/refmon/schemas/common.py`. Adding a key means changing both.

| Key | Used on | Meaning |
|---|---|---|
| `source_class` | content_in, request_in, admin_input, exec | one of the C2 source classes |
| `signed` | exec | `true`, `false` or `unknown`: the launched file has a valid code signature, as determined by the sensor. `unknown` (cannot check) raises no signal and is never treated as false. Anything else is rejected. |
| `trusted_source` | content_in | name of the `trusted_sources` rule that matched (set by Observe; origin only) |
| `destination_class` | net_connect | name of the matching policy `destinations` class, or `unknown` (set by Observe) |
| `exec_class` | exec | name of the matching policy `executables` class, or `unknown` (set by Observe) |
| `protected_asset` | asset_access | name of the matching policy `protected_assets` entry (set by Observe) |
| `threat_list_hit` | net_connect, content_in | name of a threat list, confirmed against the exact list (set by Observe) |
| `canary_hit` | request_in, asset_access | flag: a canary URL path or credential was touched (set by Observe) |
| `input_method` | user_input | `paste`, `typed`, ... |
| `launched_via` | exec | `run_dialog`, ... |
| `hidden_window`, `encoded_payload` | exec | obfuscation hints (replaced by the measured features below in Phase 4b) |
| `entropy_bits`, `encoded_char_ratio`, `longest_ws_run` | exec, content_in | obfuscation features measured in Observe before content is dropped (C11.7) |
| `path_group`, `web_root` | file_write | which configured location was written |
| `executable`, `new_file` | file_write | what kind of write |
| `persist_kind` | persist | `startup_entry`, ... |
| `bytes` | response_out | size of the response; never content |

`destination_trusted` is not an attribute. It is derived: true when `destination_class` names a `destinations` class with `trusted: true`.

## Raw attributes (RawEvent only)

Observe consumes these and never emits them: `domain` (source of content), `host` and `ip` (destination of a connection), `url_path` (path of a request), `program` (name of an executed program) and `signer` (who signed a file). A sensor cannot set the keys Observe owns (`trusted_source`, `destination_class`, `exec_class`, `protected_asset`, `threat_list_hit`, `canary_hit`); whatever it sends under those names is discarded.
