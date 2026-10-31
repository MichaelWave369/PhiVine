# PhiVine Rung 2: Governed Launch Proposal Contract

**Status:** Alpha. **Schema:** phivine.launch_plan.v0.1.

## Purpose

PhiVine now creates a machine-readable, read-only *proposal* describing what a potential future Wine launch would request. The proposal is NOT a runnable shell command, approval, security assessment, or guaranteed compatible launch. The Rung 1 file inspector remains the evidence source. PhiOS App Platform v0.58 profiles *public source repositories*, a separate use case.

## Commands

    PYTHONPATH=src python -m phivine plan ./legacy.exe
    PYTHONPATH=src python -m phivine plan ./legacy.exe --request-network

Both commands are offline, have no subprocess execution and do not write files. The optional network flag records a request, not a granted permission.

## Fields and meaning

- **proposal_id**: deterministic SHA-256-derived identifier over the canonical proposal body.
- **artifact**: observed absolute path, SHA-256, size, architecture and format. These observations may be stale; no file descriptor is pinned.
- **runner**: Wine requested, detection on PATH only; no runtime identity, version, trust, or functionality verification.
- **proposed_effects**: read from observed input path, proposed SHA-derived isolated prefix path under the user's local application state, no other host filesystem access requested, network denied by default or separately requested for human review.
- **decision**: always HELD, never authorized or executable.
- **required_before_execution**: eight future verification and authorization gates, still unimplemented.

The prefix is only a named future write target: no directory is created and it is not a sandbox. A real executor must independently revalidate bytes, paths, permissions, runner identity and isolation.

## Status propagation

A minimally recognized x86/x86_64 PE .exe and discovered Wine command produces HELD_NO_VERIFIED_EXECUTION_BOUNDARY. All other Rung 1 statuses are carried through as HELD_INSPECTION_<R1_STATUS> (including absent runner, malformed PE, unsupported architecture, unsupported extension, and MSI review candidate).

The inspector performs minimal PE/COFF header checks, not full PE validation, malware detection, or MSI parser validation. No status means the program is safe or known to work.

## Future execution gates

1. Exact artifact bytes and digest revalidated during execution, avoiding hash/execution race.
2. Wine runtime binary identity/version attested, not inferred from PATH.
3. Independently verified Linux sandbox and separately privileged broker, not merely a Wine prefix.
4. Enforced filesystem, network and device boundaries.
5. Explicit, scoped human authorization.
6. Single-use, effect-bound PhiOS lease with independent revalidation.
7. Process lifecycle, timeout, termination and cleanup verification.
8. Independent post-effect verification and narrow auditable receipts.

No future component may interpret proposal JSON as authorization or as proof of effect enforcement. No execution adapter, installation path, Wine invocation, or PhiOS authority integration exists in Rung 2.

## Known limitations

Symlink inputs are rejected by Rung 1, but this is not a TOCTOU-safe security boundary. Parent-directory symlinks and file mutation are not comprehensively checked. Absolute file paths printed to stdout may reveal local information; nothing uploads the report. The runtime search is PATH-only. No Proton, DXVK, Wine prefix lifecycle, device access, Windows registry, network isolation, or trusted launch broker is provided. The original PhiVine code is MIT; upstream compatibility components keep their own licenses.

## Testing

    PYTHONPATH=src python -m unittest discover -s tests -v

All CI test fixtures use synthetic PE headers; no Windows binaries are executed.
