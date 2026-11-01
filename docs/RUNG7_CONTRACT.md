# PhiVine Rung 7: PhiOS advisory handoff contract

Status: v0.7.0a1, contract-only integration candidate.
Schema: phivine.phios_advisory.v0.1.
Schema file: contracts/phivine.phios_advisory.v0.1.schema.json.

## Purpose and non-goals

PhiOS App Platform v0.58 currently classifies PUBLIC SOURCE REPOSITORIES using phios.repo_profile.v0.1 and phios.repo_compatibility.v0.1. It does not supply a qualified Windows binary import interface. Its Linux release contract also explicitly says the preview has no general desktop effect executor or effect-lease issuance.

PhiVine's handoff is a DIFFERENT INPUT CLASS: a report on one locally observed Windows binary candidate, an optional staged snapshot and an optional local Wine runner observation. It is NOT a phios.repo_profile, a manifest for auto-install, an adapter registration, verified compatibility assessment, or an action request.

**No PhiOS repository files are changed in Rung 7.** This side produces an untrusted input format that can be reviewed when PhiOS creates a separate, explicit native binary intake endpoint. Consumers must never accept it as authority.

## CLI

    PYTHONPATH=src python -m phivine plan ./old-app.exe > proposal.json
    PYTHONPATH=src python -m phivine phios-handoff proposal.json

With optional live, read-only checks:

    PYTHONPATH=src python -m phivine phios-handoff proposal.json --store "$HOME/phivine-stage" --runner /usr/bin/wine

The --store and --runner arguments are observational. They do not install Wine, create a snapshot, invoke Wine, modify the PhiOS app registry, call a network endpoint, or generate operator approval. The command prints JSON to stdout; redirect only if the operator intentionally wants a local saved copy.

- Output is always HELD. The CLI ALWAYS EXITS 3 on a handled, syntactically valid input, even if every observed check matches. Invalid/unreadable JSON exits 2.
- handoff_id is a deterministic SHA-256 checksum over canonical JSON. It is NOT an authenticating signature.
- Absolute host paths are excluded from the handoff. The artifact basename, digest, size, format and candidate architecture are included. A filename itself can disclose information; consumers should apply their own privacy policies.
- All authority fields are hardcoded FALSE. The JSON schema constrains these to boolean const:false. No READY, APPROVED or EXECUTE state exists.
- Optional observations are freshly recomputed from the local staged file and runner candidate. Caller-supplied verified receipts are not accepted.
- Invalid or altered plans fail closed without consulting optional filesystem paths.

## Proposed PhiOS consumer mapping

| PhiVine advisory | Future PhiOS use, IF separately implemented |
| --- | --- |
| schema and handoff_id | Validate as UNTRUSTED advisory input, not an issuer identity |
| artifact | Review-only display of filename, hash, size, and candidate architecture |
| requested_effects | Show operator the request, never grant it |
| observations | Show checks, noting they may be stale and require fresh target-host verification |
| authority | Keep every field false; never convert to a lease or permission |
| required_before_execution | Show unresolved gates, never silently skip them |

**Do not** convert this record into SUPPORTED_AFTER_OPERATOR_APPROVAL, AppIntakeResult, build execution, installation, an allowlist, or PhiOS Linux effects without a NEW versioned consumer contract, separate authority and independent verification.

## Security limitations

No Windows binary, Wine runtime, script wrapper, untrusted shell command or arbitrary executable is executed by the handoff. Source and staged matching are momentary observations, not immutable pins. Runner hashes and ELF magic do not establish authentic Wine provenance, version or safety. Rung 3's Bubblewrap fixture does not qualify a production sandbox.

A future PhiOS implementation must independently validate input limits and provenance, pin execution bytes, attest Wine and dependencies, enforce real namespaces/seccomp/capabilities/OS identities and filesystem/network policy, authenticate human operator consent, issue single-use effect-bound leases, and independently verify process outcomes and receipts. These remain separate release gates.

## Testing

    PYTHONPATH=src python -m unittest discover -s tests -v

Adversarial cases include forged plans, unchanged and changed source/stage, runner scripts, path redaction, deterministic output, full-evidence HELD decision, no subprocess, and CLI fail-closed exit code.

Original PhiVine code: MIT. Upstream compatibility binaries and dependencies are independently licensed.
