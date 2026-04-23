"""Test configuration for p2pd test suite."""
import unittest

from aionetiface.testing import AsyncTestCase

if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    unittest.IsolatedAsyncioTestCase = AsyncTestCase
