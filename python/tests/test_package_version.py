"""Package metadata consistency tests (no shared library required).

pygosqlx declares its version in three places: pyproject.toml (the source of
truth used by pip/PyPI), setup.py, and ``pygosqlx.__version__``. These tests
keep them from drifting apart.
"""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pygosqlx

_PYTHON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def _read(name: str) -> str:
    with open(os.path.join(_PYTHON_DIR, name), encoding="utf-8") as f:
        return f.read()


def _pyproject_version() -> str:
    text = _read("pyproject.toml")
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
        tomllib = None
    if tomllib is not None:
        return tomllib.loads(text)["project"]["version"]
    # Fallback for Python < 3.11: first `version = "..."` inside [project].
    section = re.search(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    assert section, "pyproject.toml has no [project] table"
    match = re.search(r'^version\s*=\s*"([^"]+)"', section.group(1), re.M)
    assert match, "pyproject.toml [project] has no version"
    return match.group(1)


def test_dunder_version_matches_pyproject():
    assert pygosqlx.__version__ == _pyproject_version()


def test_setup_py_version_matches_pyproject():
    match = re.search(r'version\s*=\s*"([^"]+)"', _read("setup.py"))
    assert match, "setup.py has no version= argument"
    assert match.group(1) == _pyproject_version()
