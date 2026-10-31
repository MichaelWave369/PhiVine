# ΦVine

**Local-first Windows compatibility planning for PhiOS.**

PhiVine is an experimental, MIT-licensed compatibility *orchestration* project. Its long-term goal is to let Linux-based PhiOS users run selected Windows applications using upstream tools such as Wine. It is **not** a rewrite of Wine and no Wine or Proton runtime is bundled.

## Current status: Rung 2, advisory only

PhiVine can:

- Read and hash a local executable candidate; minimally inspect PE/COFF architecture and flag unvalidated MSI compound-file candidates.
- Observe whether Wine is named on local PATH, without running it.
- Produce a deterministic launch proposal bound to observed artifact SHA-256, describing a potential Wine runner, an isolated prefix path, explicit filesystem/network access requests, and required authorization gates.
- Report held states for missing runner, unsupported files, and the absence of any verified execution boundary.

**PhiVine cannot yet run, install, sandbox, verify, or safely launch any Windows software.** A Wine prefix is not a security sandbox. An observed runtime is not proof of compatibility or permission. Every Rung 2 proposal stays HELD.

## Use locally

Python 3.11+; no third-party runtime dependencies for the CLI.

    PYTHONPATH=src python -m phivine inspect ./old-app.exe
    PYTHONPATH=src python -m phivine plan ./old-app.exe
    PYTHONPATH=src python -m phivine plan ./old-app.exe --request-network

Or install as a package with:

    python -m pip install -e .

And run the same commands with phivine rather than python -m phivine.

The network option only requests a future approval, **it never grants network access**.

## Tests

    PYTHONPATH=src python -m unittest discover -s tests -v

GitHub Actions compiles and executes the tests; all fixtures are synthetic and no unknown Windows binary is run.

## Governance and PhiOS integration

- **Capability is not authority.** All inspections and plans are read-only; they grant nothing.
- **Offline by default.** No downloads, subprocess launches, installers or network probes.
- **Explain before acting.** Typed, digest-bound evidence and explicit held reasons.
- **No imagined sandbox.** A future execution adapter must independently verify actual OS-level restrictions and obtain a human-authorized, effect-bound lease.
- **No lock-in.** Keep upstream Wine, Proton and related compatibility engines replaceable and independently licensed.

PhiOS App Platform v0.58 currently assesses public source repositories. PhiVine assesses local binary candidates. These are separate contracts: neither launches the other.

Read the [Rung 1 inspection contract](docs/RUNG1_CONTRACT.md) and [Rung 2 launch proposal contract](docs/RUNG2_CONTRACT.md) for explicit scope and security limitations.

## License

MIT for original PhiVine code and documentation. Third-party runtimes and software retain their own licenses.
