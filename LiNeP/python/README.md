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

Install the package with its test dependencies:

```text
python -m pip install -e ".[dev]"
python -m pytest -q
```

The repository is licensed under Apache-2.0. V0.1 and V0.2 protocol semantics
remain explicitly versioned and are not wire-compatible merely because both use
UDP and TCP reference planes.
