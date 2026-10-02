# Runtime registration (issue #31)

Status: local C++ reference implementation and executable conformance profile;
new extension, pending cross-language adoption. Existing V0.1 and V0.2 layouts
are unchanged. This is intranet LiNeP; SL2 provider/handshake work remains #30.

## Wire contract

`runtime_register = 6` is a connection-level envelope, with all three stream
identity fields zero. The existing 32-byte header and optional SL1 extension
apply without modification. SL1 labels describe TCP roles: the worker is the
initiator, even though REQUEST travels from router to worker.

The payload starts with four bytes: schema major `1`, minor `0`, operation,
reserved `0`. Other versions and nonzero reserved bits are rejected. It then
contains strictly increasing TLVs: uint16 tag, uint32 byte length, value, all
integers little-endian. No duplicate tags, trailing bytes or missing required
fields are allowed. The complete registration payload is at most 65536 bytes;
reason/model/embedding strings are limited to 8192 bytes, model/space lists to
2048 entries. Capacity is uint32 (zero means temporarily no admission).

| Tag | Value |
| --- | --- |
| 1 | concurrent_slots, uint32 |
| 2 | status_code, uint32: 200 accepted, 400..599 rejected |
| 3 | reason, opaque string bytes (empty permitted) |
| 4 | Complete unsigned, connection-level CAPABILITIES frame in its current canonical five-boolean layout |

Unknown tags below 0x8000 are mandatory and fail closed. Tags from 0x8000
are optional opaque extensions, retained through decode/encode. Their presence
cannot alter routing, authorization or lifecycle semantics. An extension that
requires such behavior must get a specified mandatory tag and version review.

| Operation | Direction | Required tags |
| --- | --- | --- |
| 1 register_runtime | worker -> router | 1 (nonzero), 4 |
| 2 result | router -> worker | 2, 3 |
| 3 draining | worker -> router | none |
| 4 deregister | worker -> router | none |
| 5 capacity_update | worker -> router | 1 |
| 6 capabilities_query | router -> worker | none |

Other known tags on an operation are rejected. Registration requires explicit
capabilities and capacity; it never invents a model list or authorizes a worker
by self-declaration. Model IDs and profiles must be unique and nonempty/known.
Embedding spaces must identify an advertised model and a valid dimension/metric.
CAPABILITIES replies use the existing envelope type 4 and are re-authorized.

## Reference dispatch and lifecycle

After the existing lease-validated, authenticated SESSION_BIND and confirmation,
the router constructs `runtime_registration_session` around its session_manager.
It supplies an authorizer that checks the bound credential, runtime identity,
all advertised models and embedding spaces. An absent authorizer denies every
registration. Per-device key provisioning remains the application's responsibility.
Applications requiring SL1 set `require_sl1`; the registration extension cannot
upgrade or replace authentication. Bind MAC and control-plane lease verification
must use the existing handshake path before registration dispatch.

`receive_worker()` reads a frame, verifies SL1 with initiator-to-responder labels,
checks direction and dispatches it. It closes the socket and fails all in-flight
streams on protocol violations, malformed frames, authentication failure or
disconnect. `receive_worker_frame()` supports applications with their own I/O;
those applications must close their socket when `closed()` becomes true.
Calls on this reference state and its session_manager are serialized by the
owning connection event loop.

For register_runtime, the caller sends the returned result, including a 401 for
an unbound/stale connection or 403 for denied authorization. Only register_runtime
produces a registration result; draining/update/deregister have no response.
`send_runtime_registration()` signs the result via the normal transport SL1 path.

After acceptance, router -> worker permits REQUEST, cancel and capabilities_query;
worker -> router permits EVENT, window_update and CAPABILITIES reply, plus lifecycle
operations. Before sending a router data frame, call `send_router_frame()` and
then the ordinary typed transport send method (which signs in the responder
direction). EVENT, cancel and window_update reuse session_manager stream rules.
Successful outbound validation records a request before transmission; if sending
fails, close the connection and terminate its active streams.

Admission requires an advertised model/profile, free capacity and a non-draining
runtime. Capacity exhaustion, capacity zero and draining return transient 503,
allowing the router to select another worker. DRAINING allows existing streams,
cancel and backpressure to finish; it does not permit new requests. Deregistration
is legal only after all streams are terminal. Re-registration then requires fresh
authorization. A duplicate registration on an already registered connection is a
protocol violation. Any stale or changed binding invalidates registration, even
if a subsequent re-bind repeats the same token/epoch. Re-bind must be followed
by a fresh registration; TCP/MAC roles never change.

## EQUORUS boundary and future projection

Reviewed design input: EQUORUS `docs/CONSUMER_CONTRACTS_V0_1.md`, including its
implemented `linep.v02.request` projection. EQUORUS currently has no registration
schema or adapter. This extension does not claim one and introduces no dependency
on a sibling checkout. The native wire contract remains owned by LiNeP.

A future `linep.v02.runtime_registration` EQUORUS type must have its own reviewed
schema, separate from the EQUORUS envelope version and LiNeP protocol version.
It must project operation and explicit TLV presence, capabilities, capacity,
status/reason and preserved optional extensions without inserting defaults.
Bound node/runtime uint64 IDs must use decimal strings; endpoint/capacity/status
are uint32 numbers. Opaque extension/string bytes require an explicit binary
representation or verified UTF-8 subset, never silent replacement/normalization.
Registration identity comes from the authenticated binding, not payload claims.
Caller-supplied provenance is required when the source supplies none; provenance
must never grant serving rights. The current EQUORUS pilot rejects unknown fields
and does not support binary blobs, so a lossless registration mapping needs an
explicit extension rather than placing it inside the existing request schema.

EQUORUS canonical structural bytes and detached SHA-256 integrity are independent
of LiNeP's little-endian TCP bytes. They do not provide SL1 authentication,
replay protection, leases or authorization. SL1 signs the entire actual registration
payload, including all TLVs. No existing golden LiNeP frame is redefined.

## Executable conformance profile

`ctest --test-dir build-v02 -R runtime_registration --output-on-failure`
runs `test_v02_runtime_registration`, the local `runtime_registration` profile:
literal golden frame, roundtrip/optional-extension preservation, truncation,
unknown schema/mandatory field, duplicate fields, unbound rejection, deny-by-default,
capacity admission, cancel/window_update in inverted directions, draining,
deregistration, re-bind/re-register, wrong-direction fail closed, authenticated
registration, replay and wrong MAC direction, and reference router/worker TCP exchange.
This profile is a CTest target; it is not yet a remote mode in linep-v02-conformance.
Go/Rust/Python registration codecs and downstream router/worker adoption are
separate integration work and are not claimed as verified by the C++ tests.
