# LiNeP V0.2 conformance runner

Reusable executable conformance harness for Issue #10.

Conceptual usage:

```text
linep-v02-conformance --endpoint ... --profile generate
linep-v02-conformance --endpoint ... --profile embed
```

Conformance is based on executed behavior, not endpoint self-declaration.

Initial checks:

```text
Identity
Streaming
Cancel
Terminal semantics
Backpressure
Embedding-space identity
Reconnect
Multiplex isolation
```

Only profiles whose required checks pass should be reported as conformant.

## Dual-plane SESSION_BIND

Endpoints that require a control-plane lease (`require_lease`) reject unbound
REQUESTs. Pass the endpoint's UDP control port with `--control`: the runner then
performs `NODE_HELLO -> INVITE -> LEASE_ACK`, binds every suite connection with
`SESSION_BIND`, and `--profile all` adds the `PROFILE_DUAL_PLANE` suites:

```text
linep-v02-conformance --endpoint 127.0.0.1:11435 --control 127.0.0.1:11436 --profile all
linep-v02-conformance --endpoint 127.0.0.1:11435 --control 127.0.0.1:11436 --profile dual_plane
```

| Suite | Expected wire behaviour |
|---|---|
| `DUAL_PLANE_BIND_BEFORE_LEASE_ACK` | connection-level 401 `lease_invalid`, connection closed |
| `DUAL_PLANE_DUPLICATE_BIND` | second identical bind is a no-op, REQUEST completes |
| `DUAL_PLANE_UNBOUND_REQUEST` | stream 401, connection closed |
| `DUAL_PLANE_STALE_REBIND` | after an epoch change: stream 401 `stale_binding`, connection stays open, in-band re-bind is served |
| `DUAL_PLANE_IDENTITY_CHANGE` | connection-level 401 `identity_change_on_existing_connection`, connection closed |
| `DUAL_PLANE_MALFORMED_BIND` | connection-level 400 `invalid_session_bind`, connection closed |

`DUAL_PLANE_UNBOUND_REQUEST` and `DUAL_PLANE_STALE_REBIND` require lease
enforcement; against an endpoint without it they fail by design. Without
`--control` the runner behaves as before (no binding).
