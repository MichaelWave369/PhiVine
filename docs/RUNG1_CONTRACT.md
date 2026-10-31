# PhiVine Rung 1: advisory binary inspection contract

Status: alpha prototype. Schema: \`phivine.inspection.v0.1\`.

## Goal

Make *observations* about a local installer candidate, without ever pretending that observation grants launch authority.

PhiOS App Platform v0.58 profiles public source repositories and its status \`SUPPORTED_AFTER_OPERATOR_APPROVAL\` remains a distinct contract. PhiVine v0.1 does **not** invoke that platform, register an app, mint permission, install a package, or attest compatibility.

## Inputs and limitations

- Regular local files up to 512 MiB, with \`.exe\` or \`.msi\` suffix.
- Read-only file header inspection and a streaming SHA-256 digest.
- Minimal PE signature and COFF machine inspection. This is not a complete PE validator or malware detector.
- CFB magic plus \`.msi\` extension yields **MSI candidate**, not verified MSI identity.
- Symlink inputs are explicitly rejected, but this is not race-free secure file handling and is not an isolation boundary.
- \`shutil.which("wine")\` observes a command on PATH; it does not run Wine or prove it works.
- No Proton discovery, Wine prefix creation, Steam integration, DXVK, Winetricks, execution, installer handling, network access, or Linux sandbox is implemented.

## Status model

- \`REVIEW_REQUIRED\`: recognized x86/x86_64 PE .exe and Wine found on PATH. **Not runnable/safe/compatible.**
- \`HELD_RUNTIME_MISSING\`: recognized x86/x86_64 PE .exe but no Wine command observed.
- \`HELD_MALFORMED_PE\`: invalid or truncated minimal PE signature/header.
- \`HELD_UNSUPPORTED_ARCHITECTURE\`: architecture not within the first x86/x86_64 scope.
- \`HELD_MSI_REVIEW_REQUIRED\`: CFB-pattern .msi needs real MSI validation before any recommendation.
- \`HELD_UNRECOGNIZED_FORMAT\`: unrecognized file contents.
- \`HELD_UNSUPPORTED_EXTENSION\`: unsupported filename suffix or suffix/format mismatch.

No result carries execution authority. The flags \`execution_authorized\`, \`execution_attempted\`, \`network_probed\`, and \`sandbox_verified\` are all false. No automatic remediation is permitted. Inspection errors return CLI exit code 2; a held report is still a successful observation, CLI exit 0.

## Next gate

Rung 2 should define a **separate, auditable launch proposal** with real, independently tested Linux sandbox and privilege boundaries, Wine prefix isolation, filesystem and network controls, human approval, timeout, process termination, and append-only receipts. No untrusted executable is to be launched until those gates are verified. A discovered \`wine\` path alone grants nothing.

## Licensing

PhiVine's own code is MIT. Upstream Wine, Proton, DXVK, and other components carry their own licenses and redistribution obligations. No third-party runtime is bundled.
