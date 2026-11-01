# ΦVine Rung 11 — reciprocal PhiOS static-triage contract

**Status: Review-only, no Windows execution or OS permission.**

Merged PhiOS [PR #364](https://github.com/MichaelWave369/PhiOS/pull/364)
at immutable commit `34553a6214b05e5bb6c42665d89621d13f1f0516`
introduced the bounded `phi-app review-phivine-triage` consumer for static DLL
review JSON produced by ΦVine Rung 10. PhiOS already tests the pinned ΦVine
producer, but future ΦVine PRs could drift without that consumer noticing.

This rung updates ΦVine's **existing reciprocal CI workflow**, rather than
creating a second workflow or weakening the older advisory test.

## Contracts tested on each ΦVine PR and main

1. **Original held advisory**: the existing `verify_phios_peer_contract.py`
   test now targets the immutable PhiOS #364 commit. It still checks both
   no-stage and staged/inert-runner observations and rejects forged execution
   approvals. Source schema remains `phivine.phios_advisory.v0.1`.
2. **New static DLL triage**: `verify_phios_triage_peer.py` creates
   nonfunctional synthetic PE32+ bytes with direct imports `D3D11.dll`,
   `WS2_32.dll` and unknown `MYGAME.dll`; then runs the current ΦVine
   `triage-imports` CLI and passes its actual JSON into PhiOS's pinned
   `review-phivine-triage` CLI. Both commands must exit **3 (HELD)**.
3. **Unknown dependency preservation**: PhiOS must display only graphics and
   network review areas and preserve `mygame.dll` as unclassified.
4. **Negative source evidence**: synthetic PE32 without an import directory
   and malformed PE bytes must stay held with no compatibility finding.
5. **Tampering**: an approval claim, mislabeled DLL classification, concealed
   recognized DLL, widened scan scope, duplicate JSON keys and oversized JSON
   are all rejected without granting or displaying invalid evidence.

The two GitHub Actions receipts record the exact **current ΦVine source SHA**
and the exact reviewed **PhiOS consumer SHA**. Checkout tokens are read-only
and not persisted. Only short receipt JSON is uploaded; no Windows executable,
Wine prefix, binary data, or staged files are distributed.

## Strict limits

- A held record is not trust. A SHA-256 on an arbitrary local input is not a
  digital signature or an immutable source identity.
- A recognized DLL name is **not** proof that the DLL, matching API, graphics
  backend, .NET/VC++ runtime, or any Wine/Proton environment is installed.
- No execution path, sandbox attestation, permissions, effect leases, native
  app install, registry changes, or compatibility rating is added.
- The PhiOS consumer pin is **intentionally fixed**, updated only through
  explicit review. This protects against unreviewed consumer drift but does
  not automatically validate compatibility with every future PhiOS release.

Source: `scripts/verify_phios_triage_peer.py`
Workflow: `.github/workflows/phios-peer-contract.yml`

**Ledger Above Ego. DONE Means Verified.**
