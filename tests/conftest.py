"""Backport unittest.IsolatedAsyncioTestCase for Python < 3.8."""
import asyncio
import unittest


if not hasattr(unittest, "IsolatedAsyncioTestCase"):
    class _IsolatedAsyncioTestCase(unittest.TestCase):
        """Minimal backport: runs async test/setUp/tearDown in a fresh event loop."""

        def _callAsync(self, coro):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(coro)
            finally:
                try:
                    pending = asyncio.Task.all_tasks(loop)
                    for t in pending:
                        t.cancel()
                    if pending:
                        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                finally:
                    loop.close()
                    asyncio.set_event_loop(None)

        def setUp(self):
            if hasattr(self, "asyncSetUp"):
                self._callAsync(self.asyncSetUp())

        def tearDown(self):
            if hasattr(self, "asyncTearDown"):
                self._callAsync(self.asyncTearDown())

        def run(self, result=None):
            method = getattr(self, self._testMethodName)
            if asyncio.iscoroutinefunction(method):
                original = method
                def sync_wrap():
                    return self._callAsync(original())
                setattr(self, self._testMethodName, sync_wrap)
            return super(_IsolatedAsyncioTestCase, self).run(result)

    unittest.IsolatedAsyncioTestCase = _IsolatedAsyncioTestCase
