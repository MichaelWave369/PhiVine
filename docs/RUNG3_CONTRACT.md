# PhiVine Rung 3: Linux sandbox fixture qualification

**Status:** experimental. **Report:** phivine.sandbox_probe.v0.1.

## Goal

Explore a concrete Linux isolation backend **without** running any Windows or user-supplied program. Rung 3 adds a host-local Bubblewrap (bwrap) fixture qualification command. This is a boundary test, not a launcher, security audit, runtime attestation, or production-ready sandbox.

    PYTHONPATH=src python -m phivine sandbox-check

No argument accepts an executable, shell, Wine command, or path to run. The only process permitted is Bubblewrap executing an embedded Python fixture supplied by PhiVine. A non-Linux host or unavailable bwrap/Python yields a HELD report. HELD returns exit status 3, an I/O or input error returns 2, and a narrow fixture observation returns 0.

## Fixed fixture

1. Start a temporary host-private canary file and localhost-only test listener. They exist **only** for the duration of the probe. No external network access is required.
2. Request Bubblewrap --unshare-all, --die-with-parent, --new-session, a read-only minimal OS runtime, a disposable sandbox /tmp, and no home or host /tmp filesystem bind.
3. Execute a fixed /usr/bin/python3 -I -c embedded probe using a list of arguments, never a shell.
4. Inside the fixture check: host-private file is invisible; sandbox /tmp works; a host-only loopback listener cannot be reached.
5. Parse and validate an exact boolean-only receipt. Missing, malformed, inconsistent, timed-out or failed tests all return HELD.

FIXTURE_BOUNDARY_OBSERVED_NOT_APP_READY means *only* that the named ephemeral fixture checks reported success for that host and moment. It does not qualify host filesystem security, prevent all network access, attest Bubblewrap binary identity, verify mount namespaces independently, prove seccomp, prevent file races, or permit execution of untrusted workloads. The fixture observes a denied connection to a host-local listener, not universal egress denial; implementation uses a private network namespace as an intended boundary.

No Wine, Proton, Windows binary or system installer is called. No launch proposal is upgraded, no PhiOS authority gate is opened, and every phivine plan remains HELD.

## Verification and CI

Python unit tests simulate both passing and failing receipts, rejection of host-file visibility, network reachability, missing backend, invalid receipts, timeouts and the fixed command shape. The **informational** CI fixture step attempts a real sandbox-check on the GitHub runner and records its result, but may be HELD because a temporary CI runner cannot provide unprivileged namespace support. An informational CI job succeeding is **not proof** the fixture passed; inspect the report artifact, and re-run on the exact target machine. Unit tests using mocks are not evidence of a working host sandbox.

## Unmet production launch gates

- Independently pinned/attested Bubblewrap and Wine binaries with exact versions and invocation policies.
- Explicit mount and symlink/TOCTOU defenses, verified filesystem allowlists and real network policy tests.
- Separate, restricted OS principal and trusted broker with seccomp/capability constraints.
- Per-app prefix lifecycle and disjoint host writable-path controls.
- Exact artifact rehash at launch, effect-bound human approval and single-use PhiOS execution leases.
- Bounded process execution/termination, receipts and independent post-effect verification.
- Real-machine validation of host attack surface, failure modes, GPU/audio/Wayland, and packaging/licensing requirements.

**Rung 3 does not satisfy these gates.** There is no application sandbox API or executable launch command yet. Never interpret the fixture_boundary_passed field as sandbox_verified for an app.
