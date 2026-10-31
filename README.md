# ΦVine

**A local-first Windows software compatibility project for PhiOS.**

PhiVine does not reimplement Wine or bundle Windows runtimes. It is building a governed compatibility path for the Linux PhiOS desktop.

## Rung 5: Exact snapshots and runner observations

Current commands:

- `inspect path.exe`: inspect and hash a local candidate.
- `plan path.exe`: create a held launch proposal without executing anything.
- `verify-plan proposal.json`: check the current file against the proposed digest.
- `sandbox-check`: run only a fixed harmless Bubblewrap fixture.
- `stage-plan proposal.json --store /private/store`: explicitly copy matching bytes to a digest-named snapshot in an **existing user-owned 0700 directory**.
- `observe-runner /absolute/path/to/wine`: hash a candidate ELF runner without executing it.

**A snapshot is NOT immutable or trusted. A runner fingerprint is NOT an attestation. No Windows software can yet be launched through PhiVine.** All executable authority and sandbox gates remain unmet.

## Example (Linux, Python 3.11+)

```sh
PYTHONPATH=src python -m phivine plan ./old-tool.exe > proposal.json
PYTHONPATH=src python -m phivine verify-plan proposal.json
mkdir -m 700 "$HOME/phivine-stage"
PYTHONPATH=src python -m phivine stage-plan proposal.json --store "$HOME/phivine-stage"
PYTHONPATH=src python -m phivine observe-runner /usr/bin/wine
PYTHONPATH=src python -m unittest discover -s tests -v
```

Stage-plan makes one local write only on an explicit invocation. It rejects unsafe, missing or non-private store directories. Existing staged content is never overwritten. Successful snapshot reports still indicate `execution_authorized: false`. An absent runner, script wrapper, symlink or unrecognized runner is held.

Exit code 0 indicates a narrow observation or successful explicit copy, **not launch permission**. Held operations return 3; invalid/unreadable plan input returns 2.

Full contracts: [R1](docs/RUNG1_CONTRACT.md), [R2](docs/RUNG2_CONTRACT.md), [R3](docs/RUNG3_CONTRACT.md), [R4](docs/RUNG4_CONTRACT.md), [R5](docs/RUNG5_CONTRACT.md).

## Architecture

PhiOS App Platform v0.58's source-repository profiling and PhiVine's local binary workflow remain separate. Any future execution adapter must have pinned immutable bytes, verified OS-level sandboxing, real runner attestation, explicit operator authorization and effect-bound receipts.

## License

Original PhiVine code and documentation are MIT. Wine and other upstream components keep their own licensing requirements.
