"""Checks that only run against an installed pygosqlx distribution.

Enabled with ``PYGOSQLX_TEST_INSTALLED=1`` (the wheel CI sets it, see
.github/workflows/pygosqlx-release.yml). They fail, rather than skip, if the
wheel does not bundle a loadable shared library, so a broken wheel cannot
pass CI by having every library-dependent test skipped.
"""

import os
import platform

import pytest

import pygosqlx
from pygosqlx import core

pytestmark = pytest.mark.skipif(
    os.environ.get("PYGOSQLX_TEST_INSTALLED") != "1",
    reason="set PYGOSQLX_TEST_INSTALLED=1 to test an installed wheel",
)

_SOURCE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LIB_NAME = {
    "linux": "libgosqlx.so",
    "darwin": "libgosqlx.dylib",
    "windows": "libgosqlx.dll",
}.get(platform.system().lower())


def test_imported_from_installed_package_not_checkout():
    pkg_dir = os.path.dirname(os.path.abspath(pygosqlx.__file__))
    try:
        inside_checkout = os.path.commonpath([pkg_dir, _SOURCE_DIR]) == _SOURCE_DIR
    except ValueError:  # different drives on Windows: cannot be nested
        inside_checkout = False
    assert not inside_checkout, (
        f"pygosqlx was imported from the source checkout ({pkg_dir}), "
        "not from the installed wheel"
    )


def test_wheel_bundles_shared_library():
    assert "GOSQLX_LIB_PATH" not in os.environ, (
        "GOSQLX_LIB_PATH must be unset so the bundled library is used"
    )
    assert _LIB_NAME is not None, f"unsupported platform {platform.system()}"
    bundled = os.path.join(
        os.path.dirname(os.path.abspath(core.__file__)), "lib", _LIB_NAME
    )
    assert os.path.isfile(bundled), f"wheel does not bundle {bundled}"
    assert os.path.samefile(core._get_lib_path(), bundled)


def test_bundled_library_loads_and_works():
    assert pygosqlx.version()
    assert pygosqlx.validate("SELECT 1")
    assert pygosqlx.extract_tables("SELECT * FROM users") == ["users"]
    assert "postgresql" in pygosqlx.dialects()
