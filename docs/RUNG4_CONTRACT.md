# PhiVine Rung 4: exact-artifact revalidation

**Status:** advisory-only alpha. **Schema:** phivine.artifact_revalidation.v0.1.

## Purpose

Before even contemplating a launch, identify when a proposed local Windows executable has been replaced or modified since Rung 2 planning. This rung implements **one read-only revalidation observation**. It is not executable authorization or a secure stage-and-launch pipeline.

    PYTHONPATH=src python -m phivine plan ./legacy.exe > proposal.json
    PYTHONPATH=src python -m phivine verify-plan ./proposal.json

An exact-file observation reports ARTIFACT_MATCHED_STILL_NOT_RUNNABLE and exit 0. Any discrepancy (wrong SHA-256, size, symlink or invalid/tampered proposal) reports HELD_* with exit 3. Invalid/unreadable JSON itself returns exit 2. The output is structured JSON in all handled cases.

## How it works

- Verify the deterministic Rung 2 proposal checksum, schema, expected size/digest, path correspondence, narrow requested effects and all original **false** authorization flags.
- Reject proposed paths that contain dot segments, invalid components or are not absolute .exe paths.
- Open each directory from the filesystem root with directory FDs and O_NOFOLLOW, then open the final file with O_NOFOLLOW, O_NONBLOCK and O_CLOEXEC. Linux/POSIX-only: unsupported platforms fail closed.
- Require a regular file, enforce a 512 MiB size limit, compute SHA-256 from **the same open descriptor**, compare with the proposed digest using constant-time equality, and verify device, inode, size, mtime and ctime remain stable across the read.
- Close all descriptors before returning. No file copy, directory creation, subprocess, Wine invocation, network call, effect lease, prefix creation, or sandbox claim occurs.

## Limits and threat model

This checks a momentary observation only. It is not a durable pin: another process can replace or modify the file after revalidation. An attacker may manipulate a file while the read is happening, or forge Rung 2 JSON **and recompute the public checksum**; a proposal ID is not an authentication signature. Directory traversal and symlink defenses cover the snapshot open; they are not proof of a secure later execution path.

A proper future executor MUST open/pin the exact artifact in a trusted, restricted broker, revalidate it immediately before use, prevent later mutable-content swaps (e.g. verified sealed staging), verify runner identity, enforce an actual tested sandbox, obtain human approval through PhiOS, enforce a single-use effect-bound lease, and emit independently checked receipts. Rung 3's fixed Bubblewrap fixture alone cannot fulfill those requirements.

Do not interpret artifact_match_observed as an authority, trust, malware-safety, sandbox, or compatibility verdict. No user-supplied executable is launched.

## Privacy

The proposal contains local absolute file paths. PhiVine does not upload reports. The CLI example redirects the plan into a file chosen by the operator; no auto-export is performed.

## Tests

    PYTHONPATH=src python -m unittest discover -s tests -v

Tests use synthetic PE headers and check matching bytes, same-size tampering, size mismatch, deleted file, leaf and parent symlinks, forged approvals, forged filesystem scopes, changed input paths, traversal, malformed JSON and no subprocess.
