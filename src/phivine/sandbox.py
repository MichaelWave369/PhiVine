"""Fixture-only Linux bubblewrap boundary qualification.

Only an embedded, constant Python probe is executed. No user-provided program,
Windows binary, Wine runner, or shell command is accepted or launched.
Qualification never grants PhiOS authority or qualifies a production sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path
import platform
import secrets
import shutil
import socket
import subprocess
import tempfile
from typing import Callable

SCHEMA = "phivine.sandbox_probe.v0.1"
TIMEOUT_SECONDS = 8

# Python runs inside the disposable sandbox, not on the user's host. The
# caller only passes a canary *path* and a local TCP port, never executable code.
PROBE_CODE = r'''
import json
import pathlib
import socket
import sys

canary = pathlib.Path(sys.argv[1])
port = int(sys.argv[2])
host_path_visible = canary.exists()
tmp = pathlib.Path('/tmp/phivine-fixture-write')
try:
    tmp.write_text('fixture', encoding='utf-8')
    tmp_writable = tmp.read_text(encoding='utf-8') == 'fixture'
finally:
    tmp.unlink(missing_ok=True)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(0.5)
    try:
        host_loopback_reachable = s.connect_ex(('127.0.0.1', port)) == 0
    except OSError:
        host_loopback_reachable = False
print(json.dumps({
    'host_canary_visible': host_path_visible,
    'sandbox_tmp_writable': tmp_writable,
    'host_loopback_reachable': host_loopback_reachable,
}))
'''.strip()


def _held(reason: str, *, detail: str | None = None) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "status": reason,
        "fixture_boundary_passed": False,
        "windows_execution_authorized": False,
        "windows_execution_attempted": False,
        "wine_invoked": False,
        "phios_sandbox_attested": False,
        "effect_lease_present": False,
        "detail": detail,
    }


def qualify_fixture_sandbox(
    *,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    system: Callable[[], str] = platform.system,
) -> dict[str, object]:
    """Run a fixed harmless fixture in bwrap; fail closed on all uncertainties.

    The subprocess is *only* bubblewrap and the fixed Python fixture. Even a
    successful probe is not production approval for a Windows executable.
    """
    if system() != "Linux":
        return _held("HELD_LINUX_REQUIRED")
    bwrap = which("bwrap")
    python = Path("/usr/bin/python3")
    if not bwrap:
        return _held("HELD_BWRAP_NOT_FOUND")
    if not python.is_file():
        return _held("HELD_SYSTEM_PYTHON_NOT_FOUND")

    with tempfile.TemporaryDirectory(prefix="phivine-probe-") as tmpdir:
        canary_dir = Path(tmpdir) / "outside"
        canary_dir.mkdir(mode=0o700)
        canary = canary_dir / "host-private-canary"
        canary.write_text(secrets.token_hex(16), encoding="ascii")
        # Live host-only local listener; sandbox must *not* reach it.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                port = listener.getsockname()[1]
                # Minimal read-only system runtime, disposable /tmp, fresh net
                # namespace. No host /home or /tmp mount. No shell involved.
                argv = [
                    bwrap, "--die-with-parent", "--new-session", "--unshare-all",
                    "--ro-bind", "/usr", "/usr",
                ]
                for directory in ("/lib", "/lib64", "/bin"):
                    if Path(directory).exists():
                        argv.extend(["--ro-bind", directory, directory])
                argv.extend([
                    "--proc", "/proc", "--dev", "/dev",
                    "--tmpfs", "/tmp", "--clearenv",
                    "--setenv", "PATH", "/usr/bin:/bin",
                    "--chdir", "/tmp", "--",
                    str(python), "-I", "-c", PROBE_CODE,
                    str(canary), str(port),
                ])
                try:
                    result = run(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
                except subprocess.TimeoutExpired:
                    return _held("HELD_FIXTURE_TIMEOUT")
                except (OSError, ValueError) as exc:
                    return _held("HELD_BWRAP_LAUNCH_FAILED", detail=type(exc).__name__)
        except OSError as exc:
            return _held("HELD_LOCAL_LISTENER_UNAVAILABLE", detail=type(exc).__name__)

    if result.returncode != 0:
        # Do not relay unbounded tool stderr or leak paths in reports.
        return _held("HELD_BWRAP_FIXTURE_FAILED", detail=f"exit={result.returncode}")
    try:
        evidence = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError, ValueError):
        return _held("HELD_INVALID_FIXTURE_RECEIPT")
    if not isinstance(evidence, dict) or set(evidence) != {
        "host_canary_visible", "sandbox_tmp_writable", "host_loopback_reachable",
    } or any(type(value) is not bool for value in evidence.values()):
        return _held("HELD_INVALID_FIXTURE_RECEIPT")
    if evidence != {
        "host_canary_visible": False,
        "sandbox_tmp_writable": True,
        "host_loopback_reachable": False,
    }:
        return _held("HELD_FIXTURE_BOUNDARY_VIOLATION")

    return {
        **_held("FIXTURE_BOUNDARY_OBSERVED_NOT_APP_READY"),
        "fixture_boundary_passed": True,
        "observations": evidence,
        "scope": "ephemeral bwrap fixture only; NOT a Wine or PhiOS security attestation",
    }
