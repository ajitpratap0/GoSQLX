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

from setuptools import Distribution, setup
from setuptools.command.bdist_wheel import bdist_wheel


class BinaryDistribution(Distribution):
    """Distribution that ships a native library, so it is never pure."""

    def has_ext_modules(self) -> bool:
        return True


class PlatformWheel(bdist_wheel):
    """bdist_wheel that produces a ``py3-none-<platform>`` wheel."""

    def get_tag(self) -> tuple:
        _, _, platform_tag = super().get_tag()
        return "py3", "none", platform_tag


setup(distclass=BinaryDistribution, cmdclass={"bdist_wheel": PlatformWheel})
