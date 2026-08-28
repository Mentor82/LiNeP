# V0.2 implementation area

Experimental implementation for Issue #10 lives here.

Do not modify existing V0.1 source files merely to satisfy V0.2. Prefer adapters around reusable core/PAL primitives.

Planned implementation units:

- `envelopes.cpp`
- `runtime_session.cpp`
- `multiplexer.cpp`
- `backpressure.cpp`
- `conformance_support.cpp`

This directory is intentionally not wired into the root build yet. Add it behind an opt-in `LINEP_BUILD_V02` flag when the first implementation unit is ready.
