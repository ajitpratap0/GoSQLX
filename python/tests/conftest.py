"""Shared pytest configuration for the pygosqlx test suite.

By default the tests import ``pygosqlx`` from this source checkout, so they
run without installing the package (the shared library is then looked up in
``pygosqlx/lib/`` or via ``GOSQLX_LIB_PATH``).

Set ``PYGOSQLX_TEST_INSTALLED=1`` to test an installed distribution instead,
for example a wheel built by cibuildwheel. The source checkout is then kept
off ``sys.path`` and ``test_installed_wheel.py`` checks that the installed
package, not the checkout, was imported and that it bundles a loadable
library. Run pytest with ``--import-mode=importlib`` in that mode so pytest
does not put the checkout on ``sys.path`` itself.
"""

import os
import sys

SOURCE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_INSTALLED = os.environ.get("PYGOSQLX_TEST_INSTALLED") == "1"

if not TEST_INSTALLED and SOURCE_DIR not in sys.path:
    sys.path.insert(0, SOURCE_DIR)
