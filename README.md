# ΦVine

A local-first Windows compatibility planning project for PhiOS.

PhiVine integrates with upstream tools conceptually; it does not reimplement Wine. Windows program execution is not provided yet.

## Rung 4

Four commands are currently provided:

- `inspect path.exe`: read a local binary candidate and report basic header evidence.
- `plan path.exe`: produce an advisory launch proposal, always held.
- `sandbox-check`: run a fixed Linux Bubblewrap test fixture, never a user application.
- `verify-plan proposal.json`: reopen the planned file without following symlinks and compare observed SHA-256 and size with the previous plan.

A matching verification is an observation at a moment in time, not a guarantee that the input is safe or unchanged afterward. No permission to launch an executable is granted.

## Usage

Python 3.11+:

```sh
PYTHONPATH=src python -m phivine plan ./old-app.exe > proposal.json
PYTHONPATH=src python -m phivine verify-plan proposal.json
PYTHONPATH=src python -m phivine sandbox-check
PYTHONPATH=src python -m unittest discover -s tests -v
```

Verification exits zero on a matching snapshot, 3 when held, and 2 for an invalid or unreadable plan. It never runs Windows code. The sandbox-check likewise cannot launch user programs.

Contracts: [R1](docs/RUNG1_CONTRACT.md), [R2](docs/RUNG2_CONTRACT.md), [R3](docs/RUNG3_CONTRACT.md), [R4](docs/RUNG4_CONTRACT.md).

## Governance

Capability is not authority. The existing PhiOS App Platform repository classifier is separate from PhiVine's binary inspection. A future executable integration needs trusted file pinning, real sandbox controls, explicit human approvals and audited process lifecycle.

## License

PhiVine original code and documentation: MIT. External compatibility engines retain their own licenses.
