# LiNeP V0.2 deterministic mock runtime

Purpose: provide a deterministic endpoint for Issue #10 without requiring an LLM, GPU, or vendor runtime.

Planned modes include:

```text
--delay-per-event
--delta-mode
--snapshot-mode
--multi-output
--fail-after N
--duplicate-event
--out-of-order-event
--disconnect-before-terminal
--ignore-cancel
--cancel-after-accept
--slow-reader
--batch-embed N
```

The mock runtime should make races, slow-consumer behavior, cancellation, reconnect, embedding batches, and invalid event order reproducible in CI.

## Dual-plane leases

```text
linep-v02-mock-runtime --port 11435 --udp-port 11436 --require-lease
```

`--udp-port` starts the lease issuer (`lease_issuer`: NODE_HELLO -> INVITE,
LEASE_ACK) and hands its router to the TCP server, so every `SESSION_BIND` is
validated against the control plane. `--require-lease` additionally rejects
REQUESTs on unbound (401, closed) and stale (401 `stale_binding`, open)
connections. It needs `--udp-port`.

## SL1 MAC Authentication

```text
linep-v02-mock-runtime --port 11435 --require-sl1 --sl1-key 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 --sl1-key-id 1
```

`--require-sl1` enforces that all incoming `SESSION_BIND` frames carry the SL1
authentication extension (`FLAG_AUTHENTICATED`) signed with HMAC-SHA256 (`auth_seq = 1`),
responds with a signed server confirmation frame, and validates monotonic framing
on all subsequent requests and events. `--sl1-key` supplies the 32-byte (64 hex characters)
shared secret, and `--sl1-key-id` specifies the primary key identifier.

