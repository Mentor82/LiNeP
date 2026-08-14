# LiNeP V0.1.0 Mac Reference (C/C++ + Python)

Purpose: keep the Mac test partner on the exact same protocol/runtime baseline.

This reference applies to both:

1. C/C++ shared library runtime (.dylib)
2. Python bindings using the same C ABI

## Source of Truth

1. Protocol baseline: PROTOCOL_V0_1_0.md
2. Execution checklist: TODO_V0_1_0.md
3. This file: Mac-side sync and validation sequence

## Script-First Workflows

Use repository scripts as the canonical execution path.

1. Windows -> remote Mac full build and fetch:

```powershell
.\scripts\build-mac.ps1 -Target all -BuildType Release -Password <mac-password> -Fetch
```

1. Windows -> remote Mac helper flow (legacy/alternate):

```powershell
.\scripts\build-mac-remote.ps1 -BuildType Release -MacHost <ip> -MacUser <user> -MacPassword <password>
```

1. Directly on Mac (local shell):

```bash
./scripts/build-targets.sh all Release
```

1. Directly on Mac single-target examples:

```bash
./scripts/build-targets.sh macos-arm64 Release
./scripts/build-targets.sh macos-universal Release
```

## Required Baseline Markers

1. Heartbeat frame size is 19 bytes
2. Heartbeat includes: worker_score + UTC timestamp bytes (MM,DD,HH,MI,SS)
3. C ABI and Python cffi declarations match the same heartbeat layout

## Mac Sync Steps

1. Pull latest repository state on Mac.
2. Verify commit id:

```bash
git rev-parse --short HEAD
```

1. Build C/C++ library on Mac (targets as needed):

```bash
./scripts/build-targets.sh macos-arm64 Release
```

or

```bash
./scripts/build-targets.sh macos-universal Release
```

1. Run C++ tests from build folder:

```bash
ctest --output-on-failure
```

1. Prepare Python environment and run heartbeat tests:

```bash
cd python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip pytest
python -m pytest tests/test_smoke.py::test_heartbeat_roundtrip_and_validate tests/test_udp_loopback.py::test_udp_heartbeat_loopback -q
```

1. Optional UDP smoke check:

```bash
python linep_doctor.py --host 127.0.0.1 --skip-tcp
```

## Pass Criteria

- [ ] C/C++ build succeeds on Mac
- [ ] Full ctest run passes
- [ ] Python heartbeat tests pass
- [ ] Heartbeat payload length observed as 19 bytes
- [ ] No mismatch between C ABI heartbeat struct and Python cffi struct

## Report Back Template

Provide these items after the Mac run:

1. Commit hash
2. Build target used (macos-arm64 or macos-universal)
3. ctest summary line
4. Python test summary line
5. Any protocol mismatch found (yes/no)
