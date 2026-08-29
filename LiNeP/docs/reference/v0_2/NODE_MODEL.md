# LiNeP V0.2 Node Model

**Applies to: LiNeP V0.2 — CURRENT NORMATIVE BASELINE**

This chapter defines the architectural meaning of **Node**, **Runtime**, **Endpoint**, and **Scheduler/Orchestrator** in LiNeP V0.2.

## 1. Node

A **LiNeP Node** is a logical participant in a LiNeP network. It is the local coordination and exposure boundary for one or more AI runtimes and their protocol endpoints.

A node MAY represent one physical host, one VM/container boundary, one edge device, one compute server, or another logical deployment unit. Physical placement does not by itself define node identity.

A node is identified by `node_id`.

A node MAY host multiple heterogeneous runtimes.

```text
LiNeP Node
├── Ollama Runtime
├── llama.cpp Runtime
├── vLLM Runtime
└── other Runtime(s)
```

**A LiNeP Node MUST NOT be assumed to be equivalent to exactly one AI runtime.**

## 2. Runtime

A **Runtime** is a concrete AI execution environment exposed through LiNeP semantics, for example Ollama, llama.cpp, vLLM, TensorRT-LLM, or another compatible inference/runtime engine.

A runtime is identified within a node by `runtime_id`.

A runtime MAY expose one or more endpoints and MAY support different runtime profiles, models, embedding spaces, capabilities, resource constraints, or execution characteristics.

LiNeP standardizes communication with runtimes. LiNeP does not require heterogeneous runtimes to share an internal architecture.

## 3. Endpoint

An **Endpoint** is a protocol-visible execution or service endpoint belonging to a runtime and identified by `endpoint_id`.

The control-plane identity hierarchy is therefore:

```text
node_id
  └── runtime_id
       └── endpoint_id
```

Together with the current runtime incarnation:

```text
ControlIdentity =
(node_id, runtime_id, endpoint_id, control_epoch)
```

A control-plane lease additionally binds an authorized incarnation to the corresponding TCP data-plane session/trunk.

## 4. Scheduler / Orchestrator

**Scheduler** and **Orchestrator** describe node functions or roles; they are not required to be separate LiNeP network identities.

A node MAY contain scheduling/orchestration logic that:

- discovers local or reachable runtimes;
- consumes capability advertisements;
- tracks availability, health, load, and queue state;
- evaluates routing policy;
- manages control-plane leases and incarnations;
- selects a suitable runtime/endpoint for new work;
- binds selected control-plane state to the TCP data plane;
- reacts to stale or unavailable runtimes without inventing execution outcomes;
- applies locality, trust, cost, energy, reliability, or failure-domain policy where supported.

Conceptually:

```text
                LiNeP Request
                     ↓
                LiNeP Node
             Scheduler / Orchestrator
              ↓        ↓        ↓
           Runtime A Runtime B Runtime C
```

The scheduler/orchestrator is therefore a **function of a node**, unless a deployment explicitly exposes such a function as its own node.

## 5. Node versus adapter

A runtime adapter such as LiNeP-Ollama is not necessarily a complete LiNeP Node.

An adapter provides the protocol/runtime integration required to expose a specific engine. A complete node may host one or more such adapters and add scheduling, orchestration, routing, health aggregation, lease management, and node-level policy.

```text
LiNeP Node
   │
   ├── Scheduler / Orchestrator
   │
   ├── LiNeP-Ollama adapter
   │      └── Ollama Runtime
   │
   ├── LiNeP-llama.cpp adapter
   │      └── llama.cpp Runtime
   │
   └── LiNeP-vLLM adapter
          └── vLLM Runtime
```

An implementation MAY combine node and adapter functions in one process. Such co-location does not collapse the architectural distinction.

## 6. Topology

LiNeP distinguishes at least three useful topology views:

- **Physical topology** — where hosts, devices, networks, and runtimes physically reside.
- **Logical topology** — which nodes, runtimes, endpoints, trunks, and relationships exist in LiNeP.
- **Capability topology** — where a requested operation/profile/model/capability can currently be satisfied.

Routing SHOULD reason primarily about the capability and logical topology rather than assuming that physical proximity alone implies suitability.

Nodes MAY be arranged hierarchically or federated, for example:

```text
Global / coordinating system
          ↓
     Regional Node
       ↓       ↓
   Edge Node  Compute Node
      ↓           ↓
   Runtime      Runtime(s)
```

Hierarchical deployment MUST NOT change the meaning of `node_id`, `runtime_id`, `endpoint_id`, `control_epoch`, lease binding, or runtime stream identity.

## 7. Separation of concerns

The following concepts are distinct and MUST NOT be conflated:

```text
Node identity        ≠ Runtime identity
Runtime identity     ≠ Endpoint identity
Node availability    ≠ Execution outcome
Capability           ≠ Availability
Availability         ≠ Authorization
Control lease        ≠ Runtime execution identity
Control epoch        ≠ Conversation/session identity
Scheduler decision   ≠ Execution ownership proof
```

In particular, a runtime becoming unavailable for **new routing** does not prove that an already-running execution has stopped or failed.

## 8. Architectural principle

LiNeP V0.2 models the network participant as a node capable of coordinating heterogeneous runtimes. Scheduler/orchestrator behavior is a node capability/function; individual runtime adapters remain replaceable implementation components beneath that node boundary.

```text
Node
  ↓ coordinates
Runtimes
  ↓ expose
Endpoints
  ↓ execute
LiNeP runtime profiles
```
