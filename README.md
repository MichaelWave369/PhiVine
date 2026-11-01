# ΦVine

**Local-first Windows compatibility tooling for PhiOS.**

PhiVine is an experimental MIT-licensed project for a future governed Windows application compatibility path. It does not replace Wine or bundle Wine, and **it cannot run Windows applications yet**.

## Rung 7: PhiOS advisory handoff

PhiVine now produces a **versioned, path-redacted, non-authorizing advisory record** that a future PhiOS native-binary intake feature could review. This is a producer-side contract, NOT a live PhiOS API integration.

The command always returns a HELD decision and exits 3, including when all optional file observations succeed. It never registers an application, installs a program, executes Wine, or creates a permission token.

```sh
PYTHONPATH=src python -m phivine plan ./old-app.exe > proposal.json
PYTHONPATH=src python -m phivine phios-handoff proposal.json

# Optional read-only checks of existing files:
PYTHONPATH=src python -m phivine phios-handoff proposal.json \
  --store "$HOME/phivine-stage" --runner /usr/bin/wine
```

Earlier commands remain: `inspect`, `plan`, `verify-plan`, `stage-plan`, `verify-stage`, `observe-runner`, `resolve-runner`, and the fixed-fixture `sandbox-check`.

The handoff record contains artifact digest/size, requested network policy, source/staged bytes observations, Wine runner observations, and every unmet authority gate. It omits absolute local paths by default. A deterministic handoff ID is only a checksum, not an authentication signature.

**Important:** PhiOS App Platform v0.58 profiles source repositories, not local Windows executables. Rung 7 does not change PhiOS or introduce a native binary import API. Any such consumer must be developed and independently qualified in PhiOS.

## Rung 9: static Windows DLL import observations

PhiVine now includes a deliberately **non-executing** PE32/PE32+ direct import
reader. Run `PYTHONPATH=src python -m phivine inspect-imports ./old-app.exe`
to observe bounded imported DLL basenames and the input file hash. The command
**always exits 3** after an observation and never loads those DLLs, launches
Wine or grants compatibility or installation authority. See
[the Rung 9 limitations and test contract](docs/RUNG9_PE_IMPORT_EVIDENCE.md).

## Rung 10: manual-review hints from direct DLL names

`PYTHONPATH=src python -m phivine triage-imports ./old-app.exe`
groups observed **direct import DLL names** into human-review areas such
as graphics, network policy, managed runtimes and compiler runtimes.
It never claims those dependencies are available or that the program
can run. The command always exits `3` (HELD) after a review.
See [Rung 10](docs/RUNG10_STATIC_DEPENDENCY_REVIEW.md).

## Rung 11: reciprocal PhiOS static-review check

The existing reciprocal CI job now tests **both** PhiVine's Rung 7 held
advisory and Rung 10 static DLL triage output against the exact merged
PhiOS Rung 11 reader, with deliberately inert PE fixtures. Neither
contract grants execution or compatibility. See
[Rung 11 reciprocal acceptance](docs/RUNG11_PHIOS_TRIAGE_RECIPROCAL.md).

## Tests

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

No tests launch Windows binaries, Wine, or untrusted script wrappers. CI's optional Bubblewrap fixture is informational and never considered a production sandbox qualification.

Read the detailed [Rung 7 contract](docs/RUNG7_CONTRACT.md), the [JSON schema](contracts/phivine.phios_advisory.v0.1.schema.json), and earlier [Rung 1](docs/RUNG1_CONTRACT.md) through [Rung 6](docs/RUNG6_CONTRACT.md) specifications.

## Governance

Capability is not authority. Local file hashes, stage matching, runner symlinks, and handoff records are observational. Secure launch eventually requires exact immutable artifact binding, a separately attested Wine runtime and dependencies, verified Linux sandbox enforcement, authenticated human consent, an effect-bound PhiOS lease, and independent receipts.

## License

Original PhiVine code and documentation are MIT. Upstream runtime licenses remain independent.
