# ΦVine

**Local-first Windows compatibility planning for PhiOS.**

PhiVine is an experimental, open-source integration project intended to use established compatibility runtimes such as Wine. It does not bundle Wine, and **does not launch Windows applications**.

## Rung 6: staged copy checks and runner discovery

The project now supports six core evidence commands, with one additional experimental sandbox fixture:

- `inspect old-app.exe`: classify a local executable candidate.
- `plan old-app.exe`: create a held, non-executable proposal.
- `verify-plan proposal.json`: compare a local input against its previously observed hash.
- `stage-plan proposal.json --store /private/store`: explicitly copy matching bytes to a private SHA-named file.
- `verify-stage proposal.json --store /private/store`: independently recheck the staged file's SHA-256, size, permissions, and hardlink count without modifying it.
- `observe-runner /absolute/path` or `resolve-runner /absolute/path`: fingerprint a direct executable candidate or observe bounded runner symlink chains. Scripts are held, not executed.
- `sandbox-check`: run only a fixed harmless Bubblewrap fixture, not an app sandbox.

## Example (Linux, Python 3.11+)

```sh
PYTHONPATH=src python -m phivine plan ./legacy.exe > proposal.json
mkdir -m 700 "$HOME/phivine-stage"
PYTHONPATH=src python -m phivine stage-plan proposal.json --store "$HOME/phivine-stage"
PYTHONPATH=src python -m phivine verify-stage proposal.json --store "$HOME/phivine-stage"
PYTHONPATH=src python -m phivine resolve-runner /usr/bin/wine
PYTHONPATH=src python -m unittest discover -s tests -v
```

A successful snapshot verification establishes only a matching file **at that instant**; it never proves immutability. An ELF fingerprint does not prove the binary is Wine, verify its version or attest provenance. Symlink tracing is not race-free. Every Rung 2 launch proposal stays HELD. No Wine executable, script wrapper, or Windows binary is run by either Rung 6 command.

For fully documented limitations and the exact permission boundaries, see [R1](docs/RUNG1_CONTRACT.md), [R2](docs/RUNG2_CONTRACT.md), [R3](docs/RUNG3_CONTRACT.md), [R4](docs/RUNG4_CONTRACT.md), [R5](docs/RUNG5_CONTRACT.md), and [R6](docs/RUNG6_CONTRACT.md).

## Governance

Capability is not authority. PhiVine's local binary inspection is separate from PhiOS App Platform's repository profiling. Real execution needs sealed/pinned bytes, attested runners/dependencies, an independently validated Linux sandbox, operator approvals, narrow leases and receipts. None of those gates is satisfied merely by a successful file check.

## License

Original PhiVine code and docs: MIT. Third-party compatibility engines keep their own licenses.
