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
