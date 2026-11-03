# LiNeP Python Package

Python support for the LiNeP dual-plane protocol.

The `0.2.x` distribution exposes the V0.2 runtime protocol while retaining an
explicit V0.1 compatibility namespace:

```python
import linep
import linep.v0_1
import linep.v0_2
```

The native V0.1 C ABI is loaded only when an API that requires it is used. Pure
Python V0.2 envelope, control-plane, mock-runtime, and conformance functionality
can therefore be imported independently of a native LiNeP library.

To use a node's trunk (liara-noded linepd), which serves only leased and bound
connections and, with `auth = "required"`, only SL1-signed frames, use
`TrunkSession`. It runs the lease handshake on the control plane
(NODE_HELLO -> INVITE -> LEASE_ACK), sends SESSION_BIND, signs and verifies
every frame with the client key and keeps the lease alive with heartbeats:

```python
from linep.v0_2 import Sl1Credentials, TrunkSession

creds = Sl1Credentials.from_file("/etc/liara/keys/linep-sl1.key")  # key_id = ..., key = <hex>
with TrunkSession("192.168.178.161", credentials=creds) as trunk:
    vector = trunk.embed("task:embed-bge", "text to embed")
```

`LiNePClient` remains the client for a runtime endpoint without a lease (for
example a LiNeP-Ollama server on its own port).

Install the package with its test dependencies:

```text
python -m pip install -e ".[dev]"
python -m pytest -q
```

The repository is licensed under Apache-2.0. V0.1 and V0.2 protocol semantics
remain explicitly versioned and are not wire-compatible merely because both use
UDP and TCP reference planes.
