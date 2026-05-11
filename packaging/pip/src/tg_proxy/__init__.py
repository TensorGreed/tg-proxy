"""tg-proxy Python wrapper.

This package is a thin shim around the prebuilt tg-proxy binary that the
wheel for your platform ships. Run as a console script:

    tg-proxy --help
"""

from .__main__ import binary_path, main

__all__ = ["binary_path", "main"]
