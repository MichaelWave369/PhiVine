# ΦVine Rung 6: independent stage verification and bounded Wine runner resolution

**Status:** experimental, advisory-only. Schemas: phivine.stage_verification.v0.1 and phivine.runner_resolution.v0.1.

## Independent staged-file check

After an operator explicitly stages an artifact through Rung 5, Rung 6 can independently check the **stored copy**, even if the original installer has been moved or removed:

    PYTHONPATH=src python -m phivine plan ./old-app.exe > proposal.json
    mkdir -m 700 "$HOME/phivine-stage"
    PYTHONPATH=src python -m phivine stage-plan proposal.json --store "$HOME/phivine-stage"
    PYTHONPATH=src python -m phivine verify-stage proposal.json --store "$HOME/phivine-stage"

The verifier requires a valid held proposal, an existing user-owned private stage directory, a SHA-256-named regular file owned by the current user, no group/other permissions, no write bits, owner read access and exactly one hard link. It uses descriptor-relative no-follow opens and hashes the same descriptor while checking stable size and filesystem metadata.

A match returns **STAGE_MATCHED_NOT_IMMUTABLE_NOT_RUNNABLE** (exit 0). Missing, altered, incorrectly named, linked, symlinked, writable or exposed copies return explicit HELD statuses (exit 3). Invalid proposal JSON returns exit 2.

**This does not prove immutability or origin.** Same-user or privileged processes can chmod, unlink, swap or mutate the snapshot immediately after observation. A matching stage file is not safe or executable; no handle remains pinned. Future trusted execution must use a separate privileged broker and a proven immutable or sealed, digest-bound handoff.

## Runner symlink tracing

    PYTHONPATH=src python -m phivine resolve-runner /usr/bin/wine

Rung 5's observe-runner command holds symlink paths. Many real Wine installations use symlink chains or shell wrappers. The Rung 6 resolver now makes bounded read-only observations:

- Accept an absolute path. Inspect each component lexically using lstat, without voluntarily following an encountered symlink during the traversal.
- Follow up to 12 symbolic-link *observations*, including relative and absolute targets, recording the chain and detecting cycles/broken links.
- Fingerprint the final, no-follow regular executable path using the existing Rung 5 observer. A final ELF candidate produces **RUNNER_RESOLVED_ELF_OBSERVED_NOT_ATTESTED** (exit 0).
- A script wrapper produces **HELD_SCRIPT_WRAPPER_REVIEW_REQUIRED** (exit 3) and is NEVER executed. Missing, looping, excessive-hop or non-executable paths also remain HELD.
- Do not infer Wine installation from a blob's ELF magic, assert its version, validate signatures, inspect dependent libraries, or invoke Wine --version.

The path trace is **TOCTOU-raceable** between lstat/readlink and the final descriptor open. It is a discovery aid, not a trusted path resolution service, sandbox component, executable identity binding, verified runner provenance or authorization source.

## Still blocked

Inspection, plans, stage verification, sandbox fixture observations and runner resolution all remain separate. Neither successful command upgrades a Rung 2 HELD plan. PhiOS permission and execution broker integration is not implemented.

Rung 3's disposable Bubblewrap probe is not a production sandbox. A future engine requires exact immutable artifact binding, runner provenance and dependencies, true filesystem/network effect enforcement, human operator authorization, single-use scoped leases, timeouts/process cleanup and independent receipts.

## Testing and CI

    PYTHONPATH=src python -m unittest discover -s tests -v

Synthetic fixtures verify stage tampering, size/permissions/hardlinks, symlinks, missing store, no subprocess, direct ELF files, bounded symlink chains, cycles, shell wrappers and CLI error codes. No user Windows app, Wine binary or wrapper script is executed.

## Licenses

PhiVine original code remains MIT. Wine, Proton and other upstream software retain their respective licenses; no runtime is bundled here.
