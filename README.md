# ΦVine

**Local-first Windows compatibility planning for PhiOS.**

PhiVine is an experimental MIT-licensed compatibility orchestration project, intended eventually to let Linux-based PhiOS users run selected Windows applications through independently packaged upstream engines such as Wine. It is **not** a Wine reimplementation. No Wine, Proton or DXVK binary is bundled.

## Rung 3: Linux sandbox fixture, not an application launcher

PhiVine currently has three deliberately separate surfaces:

1. **Inspection:** inspect a local .exe/.msi candidate and observe its SHA-256 and basic PE/COFF evidence.
2. **Planning:** produce an explicit **HELD** Wine launch proposal for a reviewed artifact, including proposed prefix and filesystem/network access requests. No permission is granted.
3. **Sandbox fixture qualification:** on a Linux host with Bubblewrap, execute **only a fixed Python test** in a disposable namespace to observe a narrow filesystem/network isolation boundary. A passed fixture is **not** production Wine isolation.

**No command executes, installs, or sandboxes a Windows application.** phivine plan always stays HELD, even if phivine sandbox-check observes a fixture boundary.

## Commands

Python 3.11+, standard library only for the CLI. Linux and a separately installed bwrap executable are needed only for the optional fixture command.

    PYTHONPATH=src python -m phivine inspect ./old-app.exe
    PYTHONPATH=src python -m phivine plan ./old-app.exe
    PYTHONPATH=src python -m phivine plan ./old-app.exe --request-network
    PYTHONPATH=src python -m phivine sandbox-check

Or install the Python package with python -m pip install -e . and use phivine directly. The --request-network option is **not** network permission, only a proposed review item. A HELD sandbox-check reports JSON and exits with status 3.

## Tests

    PYTHONPATH=src python -m unittest discover -s tests -v

GitHub Actions runs Python compilation and unit tests. An informational host-local qualification step is not a pass/fail gate; read the report artifact to distinguish a held probe from an observed fixture boundary.

## Governance

- **Capability is not authority.** Analysis, planning and test-fixture observations never mint launch permission.
- **Offline by default.** Inspection and planning make no network calls, subprocess calls, downloads or filesystem writes. The fixture command uses an ephemeral local loopback test listener, with no external network traffic.
- **No imaginary sandbox.** Wine prefixes do not provide isolation. Fixture observations are insufficient to authorize an app.
- **Explicit operator decision.** A future execution adapter must require verified OS-level controls, per-effect human approval, exact-binary binding, and independent receipts.
- **Upstream stays upstream.** Wine, Proton, DXVK and other dependencies retain their own licenses and release cadence.

PhiOS App Platform v0.58 profiles public source repositories. PhiVine assesses local binary candidates. There is **no** PhiOS execution or authorization integration yet.

Read the [Rung 1](docs/RUNG1_CONTRACT.md), [Rung 2](docs/RUNG2_CONTRACT.md), and [Rung 3](docs/RUNG3_CONTRACT.md) contracts for explicit scope.

## License

MIT for PhiVine's original code and docs. Third-party software retains its own licenses.
