"""Wheel-tagging shim for pygosqlx.

All package metadata lives in pyproject.toml. This file exists only because
pyproject.toml cannot express one thing: pygosqlx bundles a native shared
library (pygosqlx/lib/libgosqlx.{so,dylib,dll}) that it loads through ctypes,
so its wheels must be platform-specific. Without this shim setuptools would
see no extension modules and tag the wheel ``py3-none-any``, which pip would
then install on platforms the bundled library cannot run on.

The library is not a CPython extension module, so it does not depend on the
Python version or ABI. The wheel is therefore tagged ``py3-none-<platform>``:
one wheel per OS/architecture serves every supported Python version.
"""

import os
import sys
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.bdist_wheel import bdist_wheel

_LIB_DIR = Path(__file__).resolve().parent / "pygosqlx" / "lib"


class BinaryDistribution(Distribution):
    """Distribution that ships a native library, so it is never pure."""

    def has_ext_modules(self) -> bool:
        return True


class PlatformWheel(bdist_wheel):
    """bdist_wheel that produces a ``py3-none-<platform>`` wheel."""

    def get_tag(self) -> tuple:
        _, _, platform_tag = super().get_tag()
        return "py3", "none", platform_tag

    def run(self) -> None:
        # Building from the sdist on a platform with no prebuilt wheel (musl,
        # 32-bit, ...) would yield a wheel without the native library. pip
        # would cache and install it, and pygosqlx would only fail at first
        # use; pip hides build-time warnings, so fail the build instead.
        if not any(
            (_LIB_DIR / f"libgosqlx.{ext}").is_file() for ext in ("so", "dylib", "dll")
        ):
            message = (
                "pygosqlx/lib/libgosqlx.{so,dylib,dll} is missing, so this "
                "wheel would not include the native library. No prebuilt "
                "pygosqlx wheel exists for this platform: build the library "
                "with pkg/cbinding/build.sh first (see 'Building from source' "
                "in python/README.md). To build anyway and point "
                "GOSQLX_LIB_PATH at a library at runtime, set "
                "PYGOSQLX_ALLOW_MISSING_LIB=1."
            )
            if os.environ.get("PYGOSQLX_ALLOW_MISSING_LIB") != "1":
                raise SystemExit(f"error: {message}")
            print(f"WARNING: {message}", file=sys.stderr)
        super().run()

setup(distclass=BinaryDistribution, cmdclass={"bdist_wheel": PlatformWheel})
