# LiNeP-SL V0.2 Group Security & Cryptographic Execution Groups

## 1. Executive Summary

This specification defines the provider-neutral, MLS-compatible (RFC 9420) group security architecture in `linep::sl::v0_2`.

In L.I.A.R.A. Cluster OS, distributed task execution involves dynamic sets of heterogeneous worker nodes (primary execution, redundant verification, quorum consensus, and failover). LiNeP-SL Group Security provides cryptographic context isolation and forward secrecy so task payloads and intermediate stream deltas are visible only to active, authorized members of the cryptographic execution group.

---

## 2. Responsibility Split

```text
LiNeP / Cluster OS Scheduler
    --> Decides WHO works (resource placement, load balancing, health)

LiNeP Consensus / Validator
    --> Decides WHICH result is accepted (majority voting, deterministic proof)

LiNeP-SL Authorization
    --> Decides WHO may perform WHICH action (capabilities, policies)

LiNeP-SL Group Security (MLS-compatible)
    --> Decides WHO can cryptographically send and receive group traffic
```

### Critical Security Invariants

1. **Epoch Separation**:
   $$\text{control\_epoch} \neq \text{security\_group\_epoch}$$
   - `control_epoch` tracks node incarnation in the UDP Control Plane (`ULNP`).
   - `security_group_epoch` tracks cryptographic membership state and key generation of the group context.
2. **Identity Separation**:
   $$\text{task\_id} \neq \text{execution\_id} \neq \text{security\_group\_id} \neq \text{security\_session\_id}$$
3. **No Authorization Shortcut**:
   Cryptographic group membership grants confidentiality/integrity over group traffic, but does **not** bypass action-level authorization checks.
4. **Forward Secrecy & Post-Compromise Security**:
   When a node is evicted (or revoked/quarantined), the group advances to $\text{epoch}_{N+1}$ with a new ratchet key. Removed members cannot decrypt or forge messages in subsequent epochs.

---

## 3. Group Profiles

| Group Profile | Type Enum | Typical Lifetime | Use Case |
| :--- | :--- | :--- | :--- |
| **Ephemeral Task** | `ephemeral_task` | Duration of single request/task | Sensitive inference, multi-stage task pipeline |
| **Long-Lived Worker** | `long_lived_worker` | Runtime daemon lifecycle | Standard inference worker pool, shared capacity |
| **Quorum Consensus** | `quorum_consensus` | Voting session | Byzantine fault tolerance, redundant cross-check |
| **Federation Boundary**| `federation_boundary` | Multi-cluster peering | Cross-organization federated inference |

---

## 4. Group Message Authenticator Binding (`LNS2_GROUP`)

The canonical little-endian byte representation for group message signatures:

```text
Offset  Size  Field
-------------------------------------------------------------
0x00    8     Magic: "LNS2GRP\0" (0x4C, 0x4E, 0x53, 0x32, 0x47, 0x52, 0x50, 0x00)
0x08    1     Version Major (0x00)
0x09    1     Version Minor (0x02)
0x0A    8     group_id (uint64 LE)
0x12    8     group_epoch (uint64 LE)
0x1A    8     sender_node_id (uint64 LE)
0x22    8     sender_runtime_id (uint64 LE)
0x2A    4     sender_endpoint_id (uint32 LE)
0x2E    4     sender_trust_domain_id (uint32 LE)
0x32    8     sender_subject_id (uint64 LE)
0x3A    1     message_class (uint8: 1=request, 2=event, 3=control)
0x3B    1     digest_algorithm (uint8: 1=SHA-256, 2=SHA-512)
0x3C    8     message_seq (uint64 LE)
0x44    2     content_digest_len (uint16 LE)
0x46    N     content_digest (N bytes)
```

---

## 5. Failover & Eviction Flow

```text
1. Coordinator creates group (Epoch 1)
2. Scheduler adds GPU-A (Primary), GPU-B (Redundant), CPU-C (Validator) (Epoch 4)
3. Coordinator sends Task Request (Epoch 4)
4. GPU-A streams intermediate Event Deltas (Epoch 4)
5. GPU-A fails hardware check / heartbeat timeout
6. Scheduler evicts GPU-A -> remove_member() advances group to Epoch 5
7. GPU-B is promoted to Primary Worker
8. GPU-B continues execution in Epoch 5 with new epoch key
9. GPU-A is cryptographically excluded from Epoch 5
```
