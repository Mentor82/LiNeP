# LiNeP-SL V0.2 Security Binding Contract

Status: **Phase A and Phase B draft implemented**, tracked by Issue #12.

## Purpose

LiNeP-SL V0.2 supplies common security semantics for heterogeneous LiNeP V0.2
runtimes and orchestrators. An Ollama, llama.cpp, vLLM, TensorRT-LLM, VINOX, or
future adapter may implement different execution internals while presenting the
same authenticated LiNeP identities and engine-neutral actions.

The primary deployment boundary is external, Internet-facing, or federated
communication beyond the trusted LiNeP intranet. LiNeP-SL augments the chosen
LiNeP transport profile and does not replace it.

## Plane separation

Control Plane bindings protect topology and scheduling facts carried by the
LiNeP V0.2 UDP profile. Data Plane bindings protect requests, events, tools,
cancellation, embeddings and other ordered semantic payloads carried by the
persistent LiNeP V0.2 data profile.

Replay state is scoped at least by security session, direction, plane, epoch,
and key generation. A sequence accepted in one plane or direction cannot make a
message in another plane or direction valid.

## Identity separation

The following identities have different ownership and lifetimes:

```text
security_session_id                 LiNeP-SL key/replay lifecycle
trust_domain_id + subject_id        authenticated principal
node_id + runtime_id + endpoint_id  Control Plane endpoint
control_epoch + lease_token         authorized endpoint incarnation
request_id + execution_id           logical runtime attempt
output_id + event_seq               semantic output ordering
fragment_seq                        transport fragmentation ordering
```

An implementation must not derive authorization merely from capability
advertisement or availability. It must evaluate the authenticated principal,
requested engine-neutral action, resource, and governing policy.

## Canonical authenticator input

Phase A defines a deterministic little-endian encoding with the domain separator
`LNS2`, contract version, plane, direction, security level, engine-neutral
action, security-session/principal identity, plane-specific identities and a
length-prefixed content digest.

The canonical encoder does not itself provide cryptography. A later negotiated
suite consumes these bytes for MAC/signature verification. Empty or oversized
digests, an unspecified digest algorithm, and structurally incomplete bindings
fail closed.

## Non-goals of Phase A

- choosing a mandatory production cipher or PKI;
- changing LiNeP V0.2 envelopes/datagrams;
- reusing LiNeP-SL V0.1 header extensions on the V0.2 wire;
- implementing adapters for a particular inference runtime;
- claiming Internet readiness before handshake, key, replay, and conformance
  phases are complete.

## Negotiation

Both peers send a structurally validated offer containing:

- LiNeP-SL contract version;
- minimum and maximum security level;
- an ordered set of supported cryptographic suites;
- LiNeP V0.2 node/runtime/endpoint identity;
- control epoch and authorized lease token;
- a fresh 32-byte nonce.

The local policy supplies its required level and suite preference order. The
negotiator chooses the highest mutually supported level and the first mutually
supported, level-appropriate suite in policy order. A missing intersection,
unsupported version, malformed offer, or result below any required minimum
fails closed.

Current identifiers reserve HMAC-SHA-256/128 for the SL1 shared-secret profile.
The X25519/Ed25519/HKDF-SHA-256 AEAD suite identifiers are eligible for SL2 and
higher profiles. These identifiers define negotiation semantics; Phase B does
not claim that their cryptographic providers are implemented yet.

The canonical `LNS2NEG` transcript binds both ordered offers, their roles,
versions, endpoints, epochs, leases, suite lists, nonces, required level and
accepted result. Phase C authenticators must verify this transcript before the
negotiated session becomes trusted for protected traffic.

## Peer authentication boundary

`identity_verifier` is the provider-neutral seam for PKI, key-store, HSM, or
federated identity implementations. A successful result identifies the exact
LiNeP endpoint, trust domain, subject, credential revision, authentication
time, expiry, and revocation state. Session establishment rejects mismatched
endpoints, revoked/expired identities, or a session lifetime exceeding either
credential lifetime.

No raw secret or private key is stored in the protocol session record.

## Security-session lifecycle

A session record binds the negotiated suite and level to both authenticated
peers, both control epochs and leases, a unique session ID, monotone security
epoch, key ID, establishment time, key activation time, and expiry.
The accepted canonical negotiation transcript is retained with the session so
Phase C proof and key-confirmation providers can bind to the exact negotiation.

The registry enforces these invariants:

- a session ID is never reused, including after expiry, revocation, or close;
- key rotation requires a strictly newer security epoch and a different key ID;
- rotation cannot extend beyond either authenticated credential lifetime;
- expired or revoked sessions cannot emit sender identities or be rotated;
- reconnect requires a new negotiation, fresh nonces, and a new session ID;
- sender identity is selected explicitly from message direction, preventing
  initiator/responder identity substitution.

Lifecycle states are `pending`, `active`, `expired`, `revoked`, and `closed`.
Phase B manages contract state only; key derivation, proof verification,
authenticator generation, and replay windows remain Phase C work.
