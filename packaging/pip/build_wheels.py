#!/usr/bin/env python3
"""Build per-platform wheels from a goreleaser dist/ directory.

Usage:
    python build_wheels.py --dist-dir ../../dist --version 1.2.3 --output ./out

For each supported (goos, goarch) combination it:
  1. Stages the pip package layout under a temp dir,
  2. Drops the matching binary into src/tg_proxy/bin/,
  3. Pins the version in pyproject.toml,
  4. Runs `python -m build --wheel` to produce a py3-none-any wheel,
  5. Re-tags the wheel with the right platform tag via `wheel tags`.

Also produces one sdist (binary-less) for completeness; users who install
from sdist will see a friendly error from the shim.

Requires `pip install build wheel` in the runtime environment.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# (goos, goarch) -> wheel platform tag
PLATFORM_TAGS: dict[tuple[str, str], str] = {
    ("linux", "amd64"):   "manylinux_2_17_x86_64.manylinux2014_x86_64",
    ("linux", "arm64"):   "manylinux_2_17_aarch64.manylinux2014_aarch64",
    ("darwin", "amd64"):  "macosx_10_12_x86_64",
    ("darwin", "arm64"):  "macosx_11_0_arm64",
    ("windows", "amd64"): "win_amd64",
    ("windows", "arm64"): "win_arm64",
}


def find_binaries(dist_dir: Path) -> dict[tuple[str, str], Path]:
    """Scan goreleaser's artifacts.json for Binary entries.

    Goreleaser writes paths relative to the cwd where it ran (typically the
    repo root, which is dist_dir.parent). Absolute paths are honored. As a
    fallback we also try resolving relative to dist_dir itself, which
    handles a few less-common goreleaser configurations.
    """
    artifacts_path = dist_dir / "artifacts.json"
    if not artifacts_path.exists():
        raise SystemExit(f"build_wheels: {artifacts_path} not found; "
                         "did goreleaser run?")
    artifacts = json.loads(artifacts_path.read_text())
    found: dict[tuple[str, str], Path] = {}
    for art in artifacts:
        if art.get("type") != "Binary":
            continue
        raw = Path(art["path"])
        candidates = []
        if raw.is_absolute():
            candidates.append(raw)
        else:
            candidates.append((dist_dir.parent / raw).resolve())
            candidates.append((dist_dir / raw).resolve())
        for c in candidates:
            if c.exists():
                found[(art["goos"], art["goarch"])] = c
                break
    return found


def pin_version(pyproject_path: Path, version: str) -> None:
    text = pyproject_path.read_text()
    new = re.sub(r'^version = "[^"]+"',
                 f'version = "{version}"', text, count=1, flags=re.M)
    pyproject_path.write_text(new)


def run(*cmd: str, cwd: Path | None = None) -> None:
    proc = subprocess.run(list(cmd), cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(
            f"build_wheels: command failed (exit {proc.returncode}): {' '.join(cmd)}"
        )


def build_one(pip_root: Path, version: str, goos: str, goarch: str,
              binary: Path, tag: str, output_dir: Path) -> None:
    with tempfile.TemporaryDirectory(prefix=f"tg-proxy-wheel-{goos}-{goarch}-") as tmp:
        staging = Path(tmp) / "pkg"
        shutil.copytree(
            pip_root, staging,
            ignore=shutil.ignore_patterns("dist", "build", "*.egg-info",
                                          "__pycache__", "out", "bin"),
        )

        bin_dir = staging / "src" / "tg_proxy" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        bin_name = "tg-proxy.exe" if goos == "windows" else "tg-proxy"
        shutil.copyfile(binary, bin_dir / bin_name)
        (bin_dir / bin_name).chmod(0o755)

        pin_version(staging / "pyproject.toml", version)

        wheel_out = Path(tmp) / "wheels"
        wheel_out.mkdir()
        run(sys.executable, "-m", "build", "--wheel",
            "--outdir", str(wheel_out), cwd=staging)

        wheels = list(wheel_out.glob("*.whl"))
        if len(wheels) != 1:
            raise SystemExit(f"build_wheels: expected one wheel, got {wheels}")
        run(sys.executable, "-m", "wheel", "tags",
            "--platform-tag", tag, "--remove", str(wheels[0]))

        # `wheel tags` rewrites the file in place with a new name.
        retagged = list(wheel_out.glob("*.whl"))
        if len(retagged) != 1:
            raise SystemExit(
                f"build_wheels: re-tag produced unexpected files: {retagged}")

        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / retagged[0].name
        shutil.move(str(retagged[0]), target)
        print(f"  built {target.name}")


def build_sdist(pip_root: Path, version: str, output_dir: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="tg-proxy-sdist-") as tmp:
        staging = Path(tmp) / "pkg"
        shutil.copytree(
            pip_root, staging,
            ignore=shutil.ignore_patterns("dist", "build", "*.egg-info",
                                          "__pycache__", "out", "bin"),
        )
        pin_version(staging / "pyproject.toml", version)
        out = Path(tmp) / "sdist"
        out.mkdir()
        run(sys.executable, "-m", "build", "--sdist",
            "--outdir", str(out), cwd=staging)
        sdists = list(out.glob("*.tar.gz"))
        if not sdists:
            raise SystemExit("build_wheels: no sdist produced")
        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / sdists[0].name
        shutil.move(str(sdists[0]), target)
        print(f"  built {target.name}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dist-dir", required=True,
                    help="goreleaser dist/ directory")
    ap.add_argument("--version", required=True,
                    help="release version (no leading v)")
    ap.add_argument("--output", required=True,
                    help="output directory for wheels + sdist")
    ap.add_argument("--sdist", action="store_true",
                    help="also produce a sdist (the binary is omitted; users "
                         "are expected to install a wheel)")
    args = ap.parse_args(argv)

    pip_root = Path(__file__).resolve().parent
    dist_dir = Path(args.dist_dir).resolve()
    output_dir = Path(args.output).resolve()
    binaries = find_binaries(dist_dir)
    print(f"build_wheels: pip_root={pip_root}")
    print(f"build_wheels: dist_dir={dist_dir}")
    print(f"build_wheels: version={args.version}")

    built = 0
    for (goos, goarch), tag in PLATFORM_TAGS.items():
        binary = binaries.get((goos, goarch))
        if binary is None or not binary.exists():
            print(f"WARN: no binary for {goos}/{goarch}; skipping",
                  file=sys.stderr)
            continue
        print(f"building wheel for {goos}/{goarch} ({tag})")
        build_one(pip_root, args.version, goos, goarch, binary, tag, output_dir)
        built += 1

    if args.sdist:
        print("building sdist")
        build_sdist(pip_root, args.version, output_dir)

    if built == 0:
        print("ERROR: no wheels produced", file=sys.stderr)
        return 1

    print(f"done; {built} wheel(s){' + sdist' if args.sdist else ''} in {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
