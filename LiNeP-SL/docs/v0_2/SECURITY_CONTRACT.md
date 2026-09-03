# LiNeP-SL V0.2 Security Binding Contract

Status: **Phase A draft**, tracked by Issue #12.

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
