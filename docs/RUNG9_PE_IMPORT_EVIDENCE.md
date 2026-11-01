# ΦVine Rung 9 — static PE direct-import observations

**Status:** Read-only, advisory-only. **Not** Windows compatibility, trust,
sandbox, installer, application registration or execution authority.

This rung adds `phivine inspect-imports <file.exe>`, a bounded local
inspector for PE32 and PE32+ **direct Import Directory DLL names**. It is
intentionally separate from Rung 1's existing `phivine inspect` schema and
from Rung 7's PhiOS advisory handoff, so existing pinned cross-repository
contracts are unchanged.

## Operator use

```sh
PYTHONPATH=src python -m phivine inspect-imports ./old-app.exe
# Output: phivine.pe_imports.v0.1 JSON, exit 3 even on valid observations
```

The command opens only a local regular `.exe`, rejects a named symlink,
makes no network call, and reads a bounded number of header/table/name bytes
using one open file descriptor. SHA-256 is streamed from that same descriptor.
This is a **mutable snapshot observation, not an immutable content pin or a
signature**.

### What is and isn't measured

From the Microsoft PE/COFF file specification, the parser reads:
- DOS `MZ` header and bounded PE header offset
- PE machine type, optional-header type, section table and raw-file mapping
- `NumberOfRvaAndSizes` and data-directory index 1 (Import Directory)
- Null-terminated 20-byte Import Directory entries
- Printable, bounded DLL basenames addressed by mapped RVAs

Results return normalized direct DLL names, an observed file hash and
architecture, plus **always-false** fields for compatibility, trust,
immutability, sandbox, permission and Windows execution.

The parser **does not** read imported symbol names, ordinals, delay-loaded
imports, dynamic `LoadLibrary` calls, API-set redirects, COM registration,
Windows manifests, subsystem requirements, .NET assemblies, protected
executables or MSI containers. Thus an empty direct-import table is **not**
evidence of compatibility or self-containment. DLL names are untrusted
strings and must not be treated as host paths or requests to load libraries.

A malformed/ambiguous section mapping, missing descriptor terminator,
oversized import directory, invalid DLL name or unsupported architecture
returns a HELD observation (no partial names). Input absence, file format
extension refusal and symlink refusal return CLI error code 2.

### Bounds

- Regular local file: 1 byte through 512 MiB (same global inspection cap)
- PE header offset: max 1 MiB
- Section headers: max 96
- Import directory bytes: max 16 KiB
- DLL descriptors: max 128, **requiring** a null terminator
- DLL basename: 1–128 characters, conservative ASCII subset
- No parsing across unmapped, non-raw-backed or ambiguously overlapping
  RVA regions; no import-table execution

The default exit code **3** for this command is intentional even when DLL
names were observed: external automation must never mistake successful
static parsing for a launch approval.

### Test contract

`PYTHONPATH=src python -m unittest tests.test_pe_imports -v`, or run the
entire existing repository suite.

Synthetic 256-byte Rung 7 handshake fixtures remain unchanged. New unit
tests use **nonfunctional**, locally generated PE32 and PE32+ files with
synthetic import tables and deliberate corruption: invalid names and headers,
section overlap, out-of-file offsets, unterminated descriptors, overlong
names, unsupported architectures, symlink refusal and a CLI subprocess
blocker. No real Windows program or Wine runner is ever invoked.

Reference: Microsoft Learn, [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

**Ledger Above Ego. DONE Means Verified.**
