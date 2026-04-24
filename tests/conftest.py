"""Test configuration for p2pd test suite."""
import sys
import unittest

import pytest

from aionetiface import aionetiface_setup_event_loop
from aionetiface.testing import AsyncTestCase, allow_windows_firewall, remove_windows_firewall

aionetiface_setup_event_loop()

if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    unittest.IsolatedAsyncioTestCase = AsyncTestCase

# Python 3.12+ IsolatedAsyncioTestCase runs with asyncio debug=True, which
# triggers linecache.checkcache() on every call_soon via Handle.__init__.
# On Windows this makes each test take 30-60s instead of ~5s.
# Replacing checkcache with a no-op removes the overhead without affecting
# asyncio debug semantics that tests actually rely on.
if sys.version_info >= (3, 12):
    import linecache
    linecache.checkcache = lambda filename=None: None


@pytest.fixture(scope="session", autouse=True)
def windows_firewall_rule():
    allow_windows_firewall("python-test-suite")
    yield
    remove_windows_firewall("python-test-suite")
