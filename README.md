# ΦVine

**A local-first compatibility planner for PhiOS.**

PhiVine is a proposed PhiOS compatibility layer that will eventually integrate established engines such as Wine to run selected Windows software on Linux. It is **not** a reimplementation or fork of Wine.

## Rung 1: advisory-only inspection

This repository now provides a small Python command that can inspect a local Windows executable, identify a supported PE header or a tentative MSI/compound-file candidate, hash the file, and report whether the \`wine\` command is visible on PATH.

**It does not execute, install, isolate, sandbox, download, or grant permission to run any binary.** Its advisory results are not a compatibility guarantee. The future PhiOS integration is not yet implemented.

Run without installing any dependencies:

\`\`\`sh
PYTHONPATH=src python -m phivine inspect ./example.exe
\`\`\`

Or install the CLI with \`python -m pip install -e .\` and use \`phivine inspect ./example.exe\`.

Run tests:

\`\`\`sh
PYTHONPATH=src python -m unittest discover -s tests -v
\`\`\`

The Rung 1 contract is at [docs/RUNG1_CONTRACT.md](docs/RUNG1_CONTRACT.md).

## Governing principles

1. **Capability is not authority.** Detecting a runner is not approval to run it.
2. **Offline and read-only.** Inspection performs no network requests, downloads, installations, or subprocess calls.
3. **Evidence before claim.** A file extension or located binary never establishes runtime compatibility.
4. **Fail closed.** Unknown formats, architectures, and missing runners produce explicit held statuses.
5. **Keep upstream independent.** No copy of Wine, Proton, DXVK, or their binaries is bundled.
6. **No imaginary isolation.** Future permissions need separately verified Linux-level enforcement.

PhiOS App Platform v0.58 inspects public source repositories. PhiVine Rung 1 assesses local Windows binary *candidates*; the two are currently separate.

## License

MIT for original PhiVine code. Third-party software retains its own licenses.
