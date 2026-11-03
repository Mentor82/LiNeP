# Point 5: rpi5 to VM108

The target topology is `linepd VM108:9000 -> 127.0.0.1:19653 (SSH remote forward)
-> rpi5 127.0.0.1:11436 (linep-vision)`. The new restricted account
`rpi5-vision-worker` may listen on **19653 only**, enforced in sshd Match settings
and authorized_keys. It reuses the Pi's existing worker SSH key in place; no
private key is copied. The original rpi5-worker/19651 Ollama channel is unchanged.

## Artifacts

`tools/build_bundle.py --source <commit> --output <directory>` builds a deterministic
arm64 host bundle from committed source only. It contains Python SDK + adapter,
deployment templates, licenses, source/tree identity and internal SHA256SUMS.
The archive gets its own `.sha256` sidecar. HailoRT, its driver, HEFs, NumPy and
OpenCV remain host dependencies; no pip installs on the running Pi are needed.
The bundle does not claim to authenticate itself: SHA-256 is integrity/provenance
checking within the operator's trusted transfer, not a cryptographic signature.

`build-lpkg.sh <bundle.tar.gz> <output> <sign-key>` is the second output recipe for
LIARA OS packaging hosts. It uses the same source bundle, verifies checksums,
builds an explicitly `source-packaged` aarch64 package and requires an explicit
signing key. The recipe does not enable a service or provision a tunnel. It does
not imply that a LIARA OS arm64 image currently provides HailoRT/OpenCV; validate
those host dependencies before installing there. No signing keys are accessed by
the Debian/Pi deployment.

## Controlled rollout

1. Inspect target services, ports, source versions and free disk. Save source
   commit, archive SHA and target configuration backups. Verify SHA sidecar and
   all internal SHA256SUMS before installation.
2. Extract to a new immutable `/opt/linep/linep-vision-0.1.0-<commit>-arm64` directory.
   Point `/opt/linep/linep-vision` to it. Verify the selected model and host imports.
3. Install `linep-vision.service` as a local systemd unit and enable/start it.
   Its `StateDirectory` is writable, HOME points there, and host `/tmp` is shared
   for the HailoRT socket. Verify a real image through the installed endpoint.
4. Provision the separate restricted SSH account on VM108, preserving the old
   worker account and config. Validate `sshd -t` and effective Match restrictions
   before reload. Install/enable `linep-vision-tunnel.service` on the Pi. Verify
   that 19653 is loopback-only and query the remote runtime through it.
5. Prepare a candidate linep.toml by appending `rpi5-vision.toml`, after checking
   runtime ID 9 and task `vision` are free. Validate the candidate with
   `liara-noded ports --registry <candidate>`. Test the running binary against it
   in an isolated mount namespace with private `/run/liara`, no seed peers and
   distinct control/trunk ports; do not disturb live mesh/HA.
6. Use the existing HA-safe `roll-noded-cluster.sh --restart-local` procedure:
   stop HA on both nodes, replace VM108's registry, restart linepd on VM108 only,
   wait for fresh mutual mesh, resume HA and verify QUORATE on both. Execute
   detached on VM108 so operator SSH loss cannot interrupt recovery. A failed
   readiness check must restore the old registry and recover healthy mesh before
   HA is resumed. Do not change VM107's registry or binary.
7. Check direct runtime, tunnel, signed leased production trunk, `task:vision`,
   routing records, existing runtime discovery, both HA states and registry
   checks. Do not log keys or image bytes. Full conformance remains point 6.

`tools/check_endpoint.py` verifies the detection contract at each hop. For a
trunk, specify its in-place `--key-file` and `--control-port`; the tool performs
the real UDP lease + SESSION_BIND + per-frame SL1 handshake. A test bus image is
required; it checks bus/person labels and the resolved model/revision.

## Rollback

Retain each target's prior unit/link state and registry/sshd backups with hashes.
Before reverting VM108's registry, pause HA on both nodes using the same detached
procedure; resume only after fresh mutual mesh. Stop/disable the new Vision
tunnel and runtime; restore previous units/symlink if any. Remove or disable only
the new rpi5-vision-worker authorization. Keep the existing rpi5-worker, Ollama
tunnel, host HailoRT, HEFs and unrelated services intact. Keep the immutable source
release and deployment logs for audit rather than deleting them during recovery.
