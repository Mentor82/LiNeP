# LiNeP licensing policy

## 1. Apache-2.0 project scope

Unless a file or directory carries a different notice, the following LiNeP
repository material is licensed under the Apache License, Version 2.0 in the
root [`LICENSE`](../../LICENSE):

- the LiNeP and LiNeP-SL reference implementations;
- public headers, language bindings, examples, and project-maintained generated
  bindings;
- protocol specifications, architecture documents, and other documentation;
- test code, test vectors, golden frames, fixtures, and conformance material;
- project build scripts and project-produced binary artifacts.

### Version scope

This scope expressly includes both distinct LiNeP protocol baselines:

- **LiNeP V0.1** — the frozen historical worker-protocol baseline and its native
  C/C++ implementation and C ABI; and
- **LiNeP V0.2** — the current engine-neutral runtime-interoperability baseline,
  including its C++ and Python implementations, dual-plane contract, tools,
  tests, fixtures, and conformance material.

It also includes the distinct **LiNeP-SL V0.1** security-layer baseline under
the same Apache-2.0 repository license unless a file states otherwise.
LiNeP-SL has its own version line: its V0.1 label names the current SL0-SL4
security architecture and must not be confused with either LiNeP V0.1 or
LiNeP V0.2. Package and CMake metadata for the frozen implementation use the
`0.1.x` line until a LiNeP-SL V0.2 release is deliberately produced.

Licensing all three baselines under Apache-2.0 does not merge their semantics.
LiNeP V0.1, LiNeP V0.2, and LiNeP-SL V0.1 remain separate and retain the
version and migration boundaries defined by their normative documentation.

Generated output that contains or is derived from LiNeP project code remains
subject to Apache-2.0. Data, prompts, model output, or application content sent
through LiNeP does not become Apache-2.0 merely because LiNeP transported it.
A generator may state additional terms for output that is not derived from
LiNeP code.

## 2. Independent compatible implementations

Independent compatible implementations are explicitly encouraged. An
implementation may use a different license when it is independently written
and does not copy Apache-2.0-licensed LiNeP material. Copying or adapting LiNeP
code, specification text, test vectors, or other protected material requires
compliance with Apache-2.0.

Apache-2.0 is permissive: using or linking LiNeP does not require unrelated
surrounding software to adopt Apache-2.0. The Apache-2.0 patent grant applies
only as stated in section 3 of that license. Compatibility or conformance does
not imply certification, endorsement, a trademark license, or a warranty that
all third-party patent rights have been cleared.

## 3. Specifications and conformance material

Protocol and specification text, test vectors, golden fixtures, and executable
conformance tests are Apache-2.0 unless specifically marked otherwise. They may
be copied and adapted under that license. Modified specifications or fixtures
must not be presented as the unmodified normative LiNeP baseline, and required
copyright, license, and NOTICE information must be preserved.

Passing a conformance suite is a technical result, not a grant of intellectual
property rights and not project certification unless the project establishes a
separate certification program.

## 4. Third-party material

Apache-2.0 covers LiNeP project material only. It does not relicense operating
system components, compiler runtimes, Python packages, build tools, models,
runtime engines, or any other third-party work. Each third-party component
retains its own copyright, license, notice, source-distribution, attribution,
and patent conditions.

The maintained inventory is [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
A dependency update or newly bundled binary must update that inventory and add
all required license texts and source references before release.

## 5. Contributions

Unless a contribution explicitly states otherwise and is accepted on that
basis, intentional contributions submitted to this repository are provided
under Apache-2.0, including its patent terms. Contributors must have the right
to submit their work and must identify incorporated third-party material.

## 6. Names and marks

Copyright and patent permissions do not grant permission to use project names,
logos, service marks, or other branding except as permitted by applicable law
or the separate [`TRADEMARK_POLICY.md`](TRADEMARK_POLICY.md).

## 7. Distribution and release requirements

Every official source or binary release must include, in a reasonably visible
location:

1. the root `LICENSE`;
2. the root `NOTICE`;
3. this licensing policy;
4. `THIRD_PARTY_NOTICES.md` and every license text referenced for components
   actually included in that release;
5. source or a valid corresponding-source mechanism whenever a bundled
   component's license requires it.

Python wheels must carry the project `LICENSE` and `NOTICE`. A wheel that
contains the bundled MinGW runtime DLLs must also carry their license texts.
The GitHub release-bundle workflow stages the same legal payload and runs the
repository legal-artifact check before publishing the bundle.
