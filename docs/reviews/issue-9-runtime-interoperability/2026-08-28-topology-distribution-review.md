# V0.2 Runtime Interoperability: Topology & Distribution Review

Date: 2026-08-28

Tracking: [Issue #9 — engine-neutral runtime interoperability layer](https://github.com/Mentor82/LiNeP/issues/9)

This review explores how LiNeP could scale from point-to-point runtime communication toward a distributed runtime fabric. It is deliberately non-normative: no wire format, routing algorithm, cluster protocol, or topology API is approved by this document.

The architectural analogy is inspired by biological nervous systems, but the goal is not to imitate biology literally. The useful pattern is a network with dense local connectivity, sparse long-range links, specialization, weighted routes, and hierarchical coordination rather than an all-to-all mesh.

## 1. Topology principle: clustered small-world structure

A fully connected runtime mesh does not scale well. A pure central star creates bottlenecks and large failure domains. The candidate direction is a clustered small-world topology:

```text
                 ┌──────── Cluster A ────────┐
                 │                           │
            Runtime A1 ── Runtime A2         │
                 │  \          │             │
                 │   \         │             │
                 └──── Scheduler A            │
                          │                   │
                    long-range trunk          │
                          │                   │
        ┌─────────────────┼─────────────────┐ │
        │                                   │ │
  Scheduler B                         Scheduler C
   /    |    \                         /       \
 B1     B2    B3                    C1          C2
```

Candidate properties:

- dense, low-latency communication inside a local cluster;
- a smaller number of explicit long-range links between clusters;
- local routing and admission where possible;
- global coordination only when local capabilities cannot satisfy the request;
- no requirement for every runtime endpoint to know every other endpoint.

This makes topology an architectural concern above individual sockets but below LIARA's task semantics.

## 2. Three topology layers

LiNeP should distinguish at least three views of the network.

### 2.1 Physical topology

Represents real infrastructure:

```text
hosts
NICs
LAN / WAN links
actual sockets or other transports
latency / bandwidth / reachability
```

The physical topology answers where communication can happen, not what a node means semantically.

### 2.2 Logical LiNeP topology

Represents protocol relationships:

```text
persistent sessions
clusters
trunks
routes
trust domains
runtime endpoints
scheduler relationships
```

A logical route may survive changes in the underlying physical path if the transport layer can re-establish equivalent connectivity.

### 2.3 Capability topology

Represents what the network can currently provide:

```text
reasoning
chat / generation
vision
tools
embedding space X
reranking
audio
memory access
specialized accelerators
```

LIARA should primarily reason over this layer. Application logic should not need to choose a host, IP address, runtime vendor, or accelerator directly when a compatible capability can be discovered and routed through LiNeP.

## 3. Persistent trunks and logical streams

The current implementation review found that existing TCP senders may open a new connection per call. The candidate distributed architecture should not assume that behavior is optimal for runtime interoperability.

A future LiNeP trunk may be a long-lived authenticated relationship:

```text
Node / Cluster A ====================== Node / Cluster B
                  persistent LiNeP trunk
```

Multiple independent logical executions can then be multiplexed over the same relationship:

```text
stream 41 -> chat
stream 42 -> embedding batch
stream 43 -> tool result
stream 44 -> telemetry
stream 45 -> consensus
```

Important distinction:

- the trunk is a transport/session resource;
- each logical execution retains independent request, execution, output, sequencing, cancellation, and terminal state;
- failure or cancellation of one logical stream must not terminate unrelated streams unless the trunk itself fails.

Persistent trunks require dedicated design and measurement. They are not an existing V0.1 guarantee.

## 4. Local, regional, and global routing

Capability selection can be hierarchical.

```text
LIARA request
     ↓
Can the local cluster satisfy it?
     ↓ no
Which remote cluster advertises the capability?
     ↓
Remote cluster admission / scheduler
     ↓
Selected runtime endpoint
```

This yields three candidate routing scopes:

```text
Global / inter-cluster routing
        ↓
Regional / cluster routing
        ↓
Runtime scheduling
```

A global router does not need complete live state for every model process. A cluster can advertise summarized capabilities and availability, then perform its own final endpoint selection.

This is important for large deployments because topology state grows more slowly than a flat table containing every individual GPU, model slot, worker, and transient load value.

## 5. Capability-aware cluster advertisement

A cluster may advertise aggregated capabilities rather than implementation details.

Example:

```text
cluster_id: memory-east
capabilities:
  embed:
    embedding_spaces:
      - space_id: X
        modalities: [text]
  vector_search:
    spaces: [X]
  rerank: true
availability:
  state: active
```

LIARA can then request:

```text
need:
  operation: EMBED
  embedding_space_id: X
  modality: text
```

The selected cluster may route internally to Ollama, vLLM, a dedicated embedding service, or another compatible runtime. The caller does not need to know which implementation performs the operation.

The same principle applies to reasoning, vision, tools, multimodal inference, and future runtime profiles.

## 6. Weighted routing

Logical paths are not necessarily equal. Candidate route selection may consider:

```text
latency
reliability
capability match
current load
queue depth
historical success
trust / security level
cost
energy preference
locality
```

These signals should not be collapsed into one undocumented magic score. The existing LiNeP scheduler scoring model may provide useful mechanisms, but inter-cluster routing has different semantics and may require separate policy inputs.

A route decision should be explainable enough for diagnostics and governance:

```text
selected cluster B because:
  capability match = exact
  trust level = sufficient
  queue = low
  latency = acceptable
  preferred-local cluster had no compatible model
```

## 7. Adaptive routes without uncontrolled self-modification

The nervous-system analogy suggests that frequently successful communication paths may become preferred. A safe LiNeP interpretation is adaptive routing based on observed evidence, not autonomous topology mutation without policy.

Candidate flow:

```text
observed success / latency / failures
            ↓
routing-weight proposal
            ↓
policy / governance / bounded algorithm
            ↓
effective route preference
```

The system may learn that two clusters work well together, but topology changes must remain constrained by configured trust, security, authorization, capacity, and governance rules.

Do not equate adaptive routing with Hebbian learning or claim biological equivalence. The analogy is descriptive, not normative.

## 8. Failure domains and degraded operation

Clusters should act as explicit failure domains.

Candidate behavior:

- loss of one runtime does not invalidate the whole cluster if equivalent capability remains;
- loss of a trunk invalidates only routes depending on that trunk;
- loss of a remote cluster should permit local degraded operation where possible;
- capability advertisements must expire or become stale rather than remaining permanently trusted;
- rerouting must preserve request ownership and must not silently duplicate mutating work with unknown outcome;
- retry across clusters is a policy decision, not an automatic transport side effect.

A topology layer must therefore integrate with the runtime contract's terminal, cancel, unknown-outcome, and idempotency semantics.

## 9. Security and trust-domain implications

LiNeP-SL must secure communication without turning routing topology into authorization.

Keep these concepts distinct:

```text
reachable route        != authorized route
capability advertised  != caller allowed to use it
trusted cluster        != every runtime action permitted
```

Inter-cluster trunks may cross trust domains. Route selection must therefore account for security level, federation policy, identity, and local runtime authorization before execution.

A route learned from performance history must never bypass trust or capability gates.

## 10. Relationship to the neural analogy

Useful conceptual mapping:

```text
biological analogy        LiNeP architecture concept
──────────────────────    ──────────────────────────
synaptic interaction   -> logical request/event relationship
axon / nerve path      -> persistent LiNeP session or trunk
nerve bundle           -> multiplexed trunk carrying many logical streams
local neural region    -> runtime/capability cluster
long-range pathway     -> inter-cluster route
connection strength    -> bounded routing preference / weight
specialized region     -> capability-specialized cluster
```

The analogy stops at architecture. LIARA and LiNeP should not claim to reproduce neuronal computation, plasticity, consciousness, or biological learning mechanisms.

The useful lesson is organizational: specialized local structures communicate through selective, weighted long-range pathways instead of universal all-to-all connectivity.

## 11. Proposed acceptance tests — not yet executed

| ID | Scenario | Required evidence |
| --- | --- | --- |
| T01 | Two clusters expose the same capability with different latency/load | Selection follows documented routing policy and remains explainable |
| T02 | Local cluster cannot satisfy a required capability | Request is routed to a compatible remote cluster without exposing vendor-specific selection to the caller |
| T03 | One runtime inside a cluster fails | Equivalent local runtime can take over without invalidating unrelated cluster capability |
| T04 | Inter-cluster trunk fails with several active logical streams | All affected executions get explicit transport/outcome state; unrelated trunks remain active |
| T05 | Cancel one multiplexed execution | Only the owned logical execution is cancelled; sibling streams survive |
| T06 | Capability advertisement becomes stale | Stale capability is not selected until refreshed or revalidated |
| T07 | Fast route is unauthorized by policy | Authorized slower route is selected or request is rejected; routing weight never bypasses policy |
| T08 | Historical success increases route preference | Preference change remains bounded, observable, and reversible |
| T09 | Remote execution disconnects after a mutating operation may have begun | Unknown outcome is preserved; no automatic duplicate execution |
| T10 | Embedding request requires space X across multiple clusters | Only endpoints guaranteeing compatible embedding-space identity are eligible |
| T11 | Persistent trunk carries chat, embedding, telemetry, and consensus concurrently | Independent sequencing, ownership, backpressure, cancel, and terminal states are preserved |
| T12 | Large deployment advertises many runtime endpoints | Global routing can operate on summarized cluster state without requiring full per-runtime state propagation |

## 12. Open architecture decisions

- Define what constitutes a cluster and whether membership is static, configured, discovered, or negotiated.
- Decide whether inter-cluster routing belongs to the existing scheduler or a distinct topology/router component.
- Define persistent trunk negotiation, reconnect, multiplexing, and stream ownership semantics.
- Define capability advertisement aggregation and expiry/staleness rules.
- Define route metric inputs and whether a common scoring contract is needed.
- Decide how adaptive route weighting is bounded, persisted, reset, and governed.
- Define topology visibility: which peers may learn physical, logical, and capability-level information.
- Define failure-domain propagation and explicit degraded-state semantics.
- Prove that topology optimization does not weaken request identity, cancellation isolation, LiNeP-SL policy, or unknown-outcome handling.

## Design test

A successful distributed LiNeP architecture should allow LIARA to ask:

> Where is a currently available, authorized, sufficiently trusted capability that can satisfy this request?

without application code needing to ask:

> Which host, IP address, runtime vendor, process, or GPU should I call?

The topology layer should determine a valid path while preserving the runtime contract and security boundaries.