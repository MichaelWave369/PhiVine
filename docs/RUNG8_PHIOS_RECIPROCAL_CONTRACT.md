# ΦVine Rung 8 — reciprocal pinned PhiOS reader contract

**Status:** Cross-repository review-only compatibility. No Windows execution.

The PhiOS Rung 9 test in merged PR #363 already checked **PhiVine source pin**
`31d5056fb2b24fdf8cbe9e84bc408039f1de355f` against PhiOS's
advisory reader. This rung adds **reciprocal CI on PhiVine PRs**:
current PhiVine source must produce handoffs accepted, but **never
authorized**, by the immutable PhiOS Rung 9 reader pinned at
`8ce70d2425b1c3b1de08f8e80cc9df65f03f525f`.

## Actual test

The read-only GitHub Action:

1. Checks out the current PhiVine PR or main commit, plus the exact pinned PhiOS
   consumer commit (no mutable `main` dependencies or shared secrets).
2. Creates a deliberately nonfunctional 256-byte synthetic PE header as an
   input file and calls the real `phivine plan` CLI. This never executes it.
3. Calls `phivine phios-handoff` **without staging or runner**, requires exit 3
   and the expected HELD status, and passes the raw output to the real
   `python -m phios.apps.cli review-phivine` consumer.
4. Runs a separate branch through `phivine stage-plan`, using a disposable
   directory for synthetic test bytes; creates an inert ELF-header-only file
   for `--runner` observation, never invokes it.
5. Requires all stage and runner observations to remain advisory and the real
   consumer to return `HELD_NATIVE_WINDOWS_BINARY_INTAKE_UNAVAILABLE`, exit 3.
6. Recomputes a fake handoff checksum after forging
   `execution_authorized=true`, and confirms PhiOS rejects the tampered
   advisory without displaying the untrusted artifact.
7. Publishes only a bounded review JSON receipt. It does **not** upload the
   fake PE file, fake runner, Windows binaries, Wine prefix, stages or model data.

**Boundary:** This test is a producer/consumer API compatibility check, not a
trusted-origin signature, Windows compatibility proof, sandbox attestation,
permission, install authorization, or real OS/VM execution receipt.

### Scope and future updates

The producer under test changes with each PhiVine PR; the PhiOS peer commit is
**deliberately pinned** and must be updated only after independently reviewing
a new consumer version. A passing pinned compatibility test does **not**
automatically validate newer PhiOS releases. Both repositories must maintain
their independent security tests.

See `scripts/verify_phios_peer_contract.py` for the executable evidence
contract and `.github/workflows/phios-peer-contract.yml` for the hosted CI job.

**Ledger Above Ego. DONE Means Verified.**
