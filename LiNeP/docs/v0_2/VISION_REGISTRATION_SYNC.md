# Vision registration synchronization

Base: `fc2446a9ecb0e522047d1d4b8feb1976dc16c021`.
Planner: `25e08b24-b9e5-4e1d-92ed-5e27e1bc8d90`.

The Vision wire allocation (profile 4 / result 13) already exists in the base,
but the dynamic registration validator still allowed only profiles 1..3.
This delta enables profile 4 and validates the associated capability descriptors
before registration/authorization. It does not change wire IDs or add a backend.

For registration, profile 4 and a nonempty supported_vision_models list must
occur together. Every vision model must also occur in supported_models, have a
unique model ID, detect task, nonempty model/label-set IDs, <=256-byte strings,
1..1000 maximum detections, and bounded custom labels. Vision descriptors count
against the existing 64 KiB registration limit. Result/drain/query envelopes may
not hide vision capabilities in an otherwise empty descriptor.

The original Vision result validator remains unchanged, including its handling
of omitted labels. This registration check does not reinterpret detection labels
or claim that a model is actually installed; the authorizer still decides access.

Validation: fresh GNU C++ 13.2.0 Release build, 41/41 CTests passed on Windows,
including registration roundtrip/lifecycle, malformed descriptors, truncation,
profile mismatch, existing SL1/replay and socket tests. Test checks remain active
under NDEBUG. A peer review and matching Rust/vendored-C++ update are required
before declaring the shared baseline accepted. No service or rollout executed.
