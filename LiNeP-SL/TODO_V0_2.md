# LiNeP-SL V0.2 — Implementation Roadmap

Tracking: [Issue #12](https://github.com/Mentor82/LiNeP/issues/12)

Read [`V0_2_BOOTSTRAP.md`](V0_2_BOOTSTRAP.md),
[`docs/v0_2/SECURITY_CONTRACT.md`](docs/v0_2/SECURITY_CONTRACT.md), and the
LiNeP V0.2 normative reference before changing this contract.

## Phase A — contract and isolation

- [x] create isolated `linep::sl::v0_2` source/header/test paths
- [x] gate all V0.2 code behind `LINEP_SL_BUILD_V02`
- [x] define separate Control Plane and Data Plane bindings
- [x] bind security session, principal, direction and required level
- [x] bind LiNeP V0.2 control and runtime identities without merging them
- [x] define deterministic authenticator input without selecting production crypto
- [x] add fail-closed validation and initial negative tests
- [x] prove the unchanged V0.1-only build and the opt-in V0.1+V0.2 build

## Phase B — negotiation and session lifecycle

- [ ] define cryptographic suite identifiers and negotiation transcript
- [ ] define peer authentication and security-session establishment
- [ ] bind security sessions to trust domain, control epoch and authorized lease
- [ ] define rotation, expiry, revocation and reconnect behavior
- [ ] reject unsupported or downgraded profiles without fallback

## Phase C — authenticators and replay protection

- [ ] implement provider-neutral authenticator interfaces
- [ ] add independent replay windows per session, direction and plane
- [ ] protect UDP Control Plane messages
- [ ] protect TCP Data Plane requests, events and controls
- [ ] prove correct `event_seq` and `fragment_seq` handling

## Phase D — authorization

- [ ] define engine-neutral action/resource vocabulary
- [ ] map advertised runtime capabilities to policy inputs, never direct grants
- [ ] deny unknown actions and resources by default
- [ ] protect tool invocation, cancellation, metrics and administrative actions
- [ ] add adapter mapping guidance without adding engine-specific wire fields

## Phase E — governance and federation

- [ ] define Internet/federation trust-boundary profiles
- [ ] bind policy and federation revisions to decisions and audit events
- [ ] define privacy-safe, tamper-evident audit records
- [ ] add attestation hooks without mandating one provider
- [ ] test revocation and policy changes during active streams

## Phase F — conformance and hardening

- [ ] publish cross-language golden vectors
- [ ] add malformed-input and fuzz coverage
- [ ] test Windows/Linux/macOS and heterogeneous runtime adapters
- [ ] benchmark each security profile against an equivalent LiNeP V0.2 baseline
- [ ] define release and migration criteria from LiNeP-SL V0.1
