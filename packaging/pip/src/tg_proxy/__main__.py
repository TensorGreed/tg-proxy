"""Locate the bundled tg-proxy binary and run it.

On POSIX we exec() so the Go process replaces the Python one — signals,
exit code, and stdio behave the same as if you ran the binary directly. On
Windows we use subprocess + forward the exit code, since execv is fragile
under cmd.exe / PowerShell.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def _bin_name() -> str:
    return "tg-proxy.exe" if os.name == "nt" else "tg-proxy"


def binary_path() -> Path:
    """Return the absolute path to the bundled tg-proxy binary.

    Raises FileNotFoundError with an actionable message when the binary is
    not present — this happens if a user installs from sdist on a platform
    we don't ship a wheel for.
    """
    pkg_dir = Path(__file__).resolve().parent
    candidate = pkg_dir / "bin" / _bin_name()
    if not candidate.exists():
        raise FileNotFoundError(
            f"tg-proxy binary not found at {candidate}. "
            "This package was probably installed from an sdist. "
            "Install a prebuilt wheel for your platform (`pip install tg-proxy`) "
            "or use `go install github.com/TensorGreed/tg-proxy/cmd/tg-proxy@latest`."
        )
    return candidate


def main() -> int:
    binary = str(binary_path())
    args = [binary, *sys.argv[1:]]
    if os.name == "nt":
        import subprocess  # imported lazily so POSIX path stays minimal
        proc = subprocess.run(args)
        return proc.returncode
    # POSIX: replace this process. Does not return.
    os.execv(binary, args)


if __name__ == "__main__":
    sys.exit(main())
