# ΦVine Rung 5: explicit snapshots and runner byte observations

**Version:** v0.5.0a1. Both capabilities are standalone experimental tools. **Neither authorizes or runs Windows software.**

## 1. Operator-requested content-addressed staging

PhiVine Rung 4 checks an input at one moment; Rung 5 provides an explicitly requested **local copy** named for the planned SHA-256, to make later use of exact bytes easier to reason about.

    # Existing and owned 0700 directory, created by the operator:
    mkdir -m 700 "$HOME/phivine-stage"

    PYTHONPATH=src python -m phivine plan ./legacy.exe > proposal.json
    PYTHONPATH=src python -m phivine stage-plan proposal.json --store "$HOME/phivine-stage"

The stage command performs a filesystem *write* only when the operator explicitly invokes it with a destination directory. It never creates the store directory, downloads dependencies, launches Wine, or executes Windows code.

The implementation:
- Checks the Rung 2 proposal schema/checksum and requires original held/no-authority fields.
- Uses Linux/POSIX no-follow directory file-descriptor traversal for both paths.
- Requires an existing directory owned by the current user, with no group/other permission bits.
- Streams the proposed source file through SHA-256 into an exclusively created private temporary file, checking regular-file type, planned size, checksum and stable metadata.
- Makes the snapshot read-only (mode 0400), publishes a SHA-named .exe via an atomic hard link that **cannot overwrite** an existing entry, then removes the temporary name.
- Reuses a matching existing snapshot after checking its bytes and revalidating the current source. Refuses conflicting names or unsafe links.
- Reports SNAPSHOT_STAGED_NOT_RUNNABLE on success; held states are machine-readable with exit 3.

**Not immutable:** an owner can change mode, replace/unlink the blob, or mount mutable storage; root can change it too. No fs-verity, sealed memfd, trusted staging broker, cryptographic publisher signature or cross-process mutation protection exists. Staging never makes the bytes trusted or launchable.

An earlier successful snapshot receipt can also become stale if the store changes. A future execution broker must independently reopen and reverify the exact staged bytes using an immutable/pinned mechanism, as close as possible to the point of use. SHA-256 is a checksum, not an origin/authenticity proof.

## 2. Candidate Wine runner observation

    PYTHONPATH=src python -m phivine observe-runner /absolute/path/to/wine

This command never invokes the candidate with '--version', and does not run any subprocess. It opens the exact path without following symlinks, observes regular-file/executable-bit status, file size, stable file metadata and SHA-256. A file beginning with ELF magic produces RUNNER_ELF_BYTES_OBSERVED_NOT_ATTESTED. A script wrapper, a symlink, malformed path or missing binary returns a held report.

This is **not** Wine version verification, trusted provenance, package signature verification, dynamic library validation, or a security review. Some real Wine installations use scripts and symbolic links; the current strict behavior holds them for later resolver design instead of blindly following wrappers.

## Future launch requirements still unimplemented

The eight Rung 2 gates remain mandatory. We do not have a production Linux effect broker, sandbox enforcement, explicit PhiOS operator approval, single-use execution lease, independent post-effect verification, supported Wine installation/runtime, or app launch. The Rung 3 Bubblewrap fixture does not qualify an application sandbox.

Stage and runner reports always contain false for execution authorization and sandbox claims. Local absolute paths may appear in reports; no report is uploaded automatically.

## Acceptance / tests

    PYTHONPATH=src python -m unittest discover -s tests -v

Tests cover same-size changed source, snapshot re-use, no-clobber collision, symlink handling, private directory enforcement, forged permissions, runner script vs ELF identification, CLI held exit codes and absence of subprocess calls. CI does not install Wine or execute a Windows executable.

**Platform:** current snapshot stage and ELF runner observation are Linux/POSIX-oriented. Future portability and Windows wrapper resolution are separate rungs. Original PhiVine code is MIT; third-party runtimes retain their own licenses.
