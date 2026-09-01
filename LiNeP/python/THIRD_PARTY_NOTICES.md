# Third-party notices and dependency review

Review date: 2026-09-01

Reviewed baseline: `a3cc6cc29484ac8e0fbd5a4602970ab7b46d9e82`

This inventory distinguishes material included in LiNeP distributions from
dependencies that users, builders, or documentation authors obtain separately.
Third-party licenses remain controlling for third-party material.

## 1. Third-party binaries included in the repository and Python package

The Windows Python package currently contains these unmodified compiler-runtime
DLLs next to `liblinep.dll`:

| File | SHA-256 | Identified upstream | Applicable terms |
| --- | --- | --- | --- |
| `LiNeP/python/linep/libgcc_s_seh-1.dll` | `89F1EAF8576F691E1AAFC8707173618A74B8C82D6D0AC17A1BE62C76A6C79AA1` | WinLibs GCC 13.2.0, x86_64 UCRT POSIX/SEH | GPL-3.0-or-later with GCC Runtime Library Exception 3.1 |
| `LiNeP/python/linep/libstdc++-6.dll` | `7B787B2436175470328E47193C292B047A4CAC9DF7AD4B5800B2F876FE305832` | WinLibs GCC 13.2.0, x86_64 UCRT POSIX/SEH | GPL-3.0-or-later with GCC Runtime Library Exception 3.1 |
| `LiNeP/python/linep/libwinpthread-1.dll` | `4BDE68FBB2C6A9A64535928FC505056EBF6F5DC44F82EA2EAAC3C714DC22CE79` | MinGW-w64 winpthreads from the WinLibs GCC 13.2.0 toolchain line | MIT plus the BSD-3-Clause-derived Lockless notice reproduced in `LIBWINPTHREAD.txt` |

The embedded compiler strings identify GCC 13.2.0 built by Brecht Sanders and
the `x86_64-ucrt-posix-seh` WinLibs configuration. The matching upstream release
line is GCC 13.2.0 / MinGW-w64 11.0.1 UCRT release 8:

- binary and source release directory: <https://sourceforge.net/projects/winlibs-mingw/files/13.2.0posix-18.1.5-11.0.1-ucrt-r8/>
- WinLibs build project: <https://github.com/brechtsanders/winlibs_mingw>
- GCC source and release archives: <https://gcc.gnu.org/pub/gcc/releases/gcc-13.2.0/>
- MinGW-w64 source: <https://sourceforge.net/projects/mingw-w64/files/mingw-w64/mingw-w64-release/>

The corresponding license texts are distributed in
`LiNeP/python/linep/licenses/`. No local source modifications to these runtime
DLLs are recorded in this repository. A distributor replacing any DLL must
record the exact new provenance, version, hash, corresponding-source location,
and license payload. Distribution of the GCC runtime libraries must also satisfy
the GPL's corresponding-source requirements; a link alone may not satisfy every
distribution method.

`LiNeP/python/linep/liblinep.dll` itself is LiNeP project output under
Apache-2.0. Dynamic use of the listed runtime DLLs does not relicense LiNeP code,
and Apache-2.0 does not relicense those DLLs.

## 2. Runtime package dependencies not copied into this repository

| Dependency | Use | Declared license | Distribution treatment |
| --- | --- | --- | --- |
| `cffi >= 1.15` | Python C ABI loading for LiNeP and LiNeP-SL | MIT No Attribution | Declared dependency; installed separately by the Python package manager |
| C/C++ standard library and operating-system APIs | Native runtime support | Toolchain/platform terms | Linux/macOS system libraries are not copied into repository artifacts; Windows exceptions are listed above |
| Windows `ws2_32` / UCRT system APIs | Sockets and C runtime | Microsoft platform terms | Referenced dynamically; not redistributed by this repository |

The current CMake graph does not fetch or vendor OpenSSL, libsodium, Boost,
zlib, JSON libraries, or another external cryptographic/network library.
LiNeP-SL's SHA-256/HMAC implementation is project code covered by Apache-2.0.

## 3. Build, test, documentation, and CI dependencies

These tools are obtained separately and are not included in LiNeP binary
releases merely because CI uses them:

| Dependency | Purpose | Declared upstream license |
| --- | --- | --- |
| CMake, Ninja, GCC/G++, LLVM/Clang, MSVC, Apple SDK, cross compilers | Native build toolchain | Respective upstream/toolchain licenses |
| `setuptools`, `wheel` | Python build backend | MIT |
| `pytest`, `pytest-timeout` | Tests | MIT |
| `Sphinx` | Documentation | BSD-2-Clause |
| `Furo`, `sphinx-autodoc-typehints`, `MyST-Parser` | Documentation | MIT |
| GitHub Actions referenced by `.github/workflows/build.yml` | CI orchestration | Each action's repository license and GitHub service terms |

Development-only use does not place these projects under Apache-2.0. If a future
release starts embedding any of them, this inventory and the release license
payload must be updated first.

## 4. Attribution and patent review result

The repository-level Apache-2.0 license provides the contributor patent grant
defined by that license for LiNeP contributions. Third-party components carry
only their own patent and warranty terms. This review found no bundled patented
codec, model, model weights, tokenizer data, or separately licensed crypto
library. It does not constitute a freedom-to-operate opinion.

The bundled GCC and MinGW-w64 runtime notices are the current attribution and
source-distribution concern. Their full notices are shipped with Python wheels
and consolidated release bundles and are checked by CI.
