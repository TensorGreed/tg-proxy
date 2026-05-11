"""Unit tests for the tg-proxy Python shim.

Run with: python -m unittest discover -s tests
"""
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


# Make src/ importable without installing the package.
SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from tg_proxy import __main__ as shim  # noqa: E402


class BinaryPathTests(unittest.TestCase):
    def test_raises_when_binary_missing(self):
        # tg_proxy/bin/ does not exist in a freshly checked-out source tree.
        with self.assertRaises(FileNotFoundError) as cm:
            shim.binary_path()
        self.assertIn("not found", str(cm.exception))
        self.assertIn("go install", str(cm.exception))

    def test_returns_path_when_binary_present(self):
        bin_dir = SRC / "tg_proxy" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        name = "tg-proxy.exe" if os.name == "nt" else "tg-proxy"
        path = bin_dir / name
        try:
            path.write_text("dummy")
            path.chmod(path.stat().st_mode | stat.S_IEXEC)
            got = shim.binary_path()
            self.assertEqual(got, path)
        finally:
            if path.exists():
                path.unlink()


class MainSmokeTests(unittest.TestCase):
    """Spawn the shim as a subprocess against a tiny fake binary."""

    def test_main_invokes_binary_and_propagates_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "tg_proxy" / "bin"
            bin_dir.mkdir(parents=True)

            if os.name == "nt":
                fake = bin_dir / "tg-proxy.exe"
                # On Windows we can't easily build an exe in-test, so use a
                # .cmd script instead and point _bin_name there.
                fake = bin_dir / "tg-proxy.cmd"
                fake.write_text("@echo off\nexit /b 7\n")
            else:
                fake = bin_dir / "tg-proxy"
                fake.write_text("#!/bin/sh\nexit 7\n")
                fake.chmod(0o755)

            # Write a __main__.py shim that re-uses our shim but with a
            # binary path pointed at the temp dir.
            runner = tmp_path / "runner.py"
            runner.write_text(textwrap.dedent(f"""
                import os, sys
                from pathlib import Path
                sys.path.insert(0, {str(SRC)!r})
                from tg_proxy import __main__ as shim
                # Point binary_path at the fake.
                shim_pkg_dir = Path({str(bin_dir.parent)!r})
                shim.__file__ = str(shim_pkg_dir / "__main__.py")
                shim._bin_name = lambda: {fake.name!r}
                sys.exit(shim.main())
            """))

            proc = subprocess.run(
                [sys.executable, str(runner)],
                capture_output=True,
            )
            self.assertEqual(proc.returncode, 7,
                             msg=f"stdout={proc.stdout!r} stderr={proc.stderr!r}")


if __name__ == "__main__":
    unittest.main()
