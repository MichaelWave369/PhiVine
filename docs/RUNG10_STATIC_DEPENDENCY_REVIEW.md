# ΦVine Rung 10: static DLL dependency review hints

**Status: HELD. Read-only and informational.**

The existing Rung 9 `inspect-imports` command parses only the bounded,
direct DLL import directory of PE32/PE32+ files. Rung 10 adds an
**interpretation layer over those observed names**, not another PE parser
or an executable-compatibility verdict.

```sh
PYTHONPATH=src python -m phivine triage-imports ./old-app.exe
# Emits phivine.import_triage.v0.1 JSON. Always exits 3 after inspection.
```

The output records the observed source SHA-256, file size, architecture,
direct imported DLL names, human-review categories and unclassified DLLs.

Recognized name categories are deliberately small:

| Manual review area | Some recognized direct DLL imports |
| --- | --- |
| Graphics API review | d3d9.dll, d3d11.dll, d3d12.dll, dxgi.dll, opengl32.dll, vulkan-1.dll |
| Network permission review | ws2_32.dll, winhttp.dll, wininet.dll |
| Managed-runtime bootstrap review | mscoree.dll, coreclr.dll, hostfxr.dll |
| C/C++ runtime review | msvcr120.dll, msvcp140.dll, ucrtbase.dll, vcruntime140.dll |
| COM/automation review | ole32.dll, oleaut32.dll, combase.dll |
| Windows UI review | user32.dll, gdi32.dll, shell32.dll, comctl32.dll |

**Interpretation:** Observing `d3d11.dll` suggests reviewing graphics API
translation. It does *not* prove a graphics API will initialize. Observing
`ws2_32.dll` suggests reviewing the app's network policy, but it **does
not** request or grant network access. Observing `mscoree.dll` is not a
guarantee of any installed .NET runtime. Unclassified imports are left
explicitly unclassified, not labeled incompatible or unsafe.

## Guardrails and non-goals

- The import table covers **direct** imports only. Delay imports, dynamic
  `LoadLibrary` calls, symbol names/ordinals, SxS manifests, managed
  assemblies and installer side effects are **not scanned**.
- Missing an import name never proves the API is unused.
- Neither source hashes nor filenames establish file origin, a signature,
  immutability or malware safety.
- All source observations and review categories are nonauthoritative.
  Every compatibility, dependency availability, sandbox, lease, permission
  and Windows execution flag remains **false**.
- The CLI intentionally returns **exit 3 (HELD)** even when names are found.
- No PE, DLL or Wine runner is executed, loaded, installed, contacted or
  downloaded. No scan results are sent over a network.
- The Rung 7 advisory schema, reciprocal PhiOS integration and all existing
  source-pinned contracts remain unchanged.

Tests use synthetic nonfunctional PE32/PE32+ headers and include negative
cases for forged authority, unsafe or duplicated names, changed parsing
scope, mismatched import counts, malformed files and attempts to invoke
external processes.

Reference: [Microsoft's PE format documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
which separates direct import tables from delay-load import directories.

**Ledger Above Ego. DONE Means Verified.**
