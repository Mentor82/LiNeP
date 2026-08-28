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
