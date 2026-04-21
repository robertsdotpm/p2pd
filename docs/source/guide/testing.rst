Testing
=========

P2PD ships with a test suite in the ``tests/`` directory.  All tests
can be run with ``pytest`` or ``unittest`` from the project root.

----

Running the test suite
------------------------

.. parsed-literal::

    # Full suite
    python3 -m pytest tests/ -v

    # Specific file
    python3 -m pytest tests/test_punch.py -v

    # Specific test
    python3 -m pytest tests/test_punch.py \
        -k test_bidirectional_ntp_synchronized_punch -v

    # unittest style (works on Python 3.5+)
    python3 -m unittest tests.test_punch -v

----

Test file reference
---------------------

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - File
     - What it covers
   * - ``test_punch.py``
     - TCP hole punching: loopback, multi-NIC IPv4, loopback IPv6,
       multi-NIC IPv6.  Includes NTP-synchronised bidirectional tests
       and actual socket creation.
   * - ``test_punch_plugin.py``
     - Integration test for the punch traversal plugin.
   * - ``test_stun_client.py``
     - STUN protocol: WAN IP discovery, port mapping, NAT classification.
   * - ``test_turn_client.py``
     - TURN client protocol.
   * - ``test_turn.py``
     - End-to-end TURN relay using the local test server.
   * - ``test_signaling.py``
     - MQTT signaling message encoding and routing.
   * - ``test_p2p_addr.py``
     - Address format parsing and serialisation.
   * - ``test_network.py``
     - Network interface detection across platforms.
   * - ``test_link_local_ip.py``
     - IPv6 link-local address handling.
   * - ``test_status.py``
     - Node status and monitoring.
   * - ``test_unit.py``
     - General unit tests (pipes, queues, utilities).
   * - ``test_p2pd_server.py``
     - Node/server integration (currently marked TODO pending fix).

----

Running the guide examples as tests
--------------------------------------

All guide examples are self-testing single-file scripts.  Run them
directly:

.. parsed-literal::

    # NAT detection
    python3 docs/examples/guide_03_nat_detect.py

    # Raw STUN request
    python3 docs/examples/guide_04_stun_raw.py

    # TCP echo server (asserts echo correctness)
    python3 docs/examples/guide_05_echo_server.py

    # UDP await style
    python3 docs/examples/guide_06_udp_await.py

----

Writing your own test
-----------------------

The test files use ``unittest.IsolatedAsyncioTestCase`` on Python 3.8+
and a compatible shim on older versions.  A minimal async test looks
like:

.. code-block:: python

    import asyncio
    import sys
    import unittest

    if sys.version_info >= (3, 8):
        AsyncTestCase = unittest.IsolatedAsyncioTestCase
    else:
        class AsyncTestCase(unittest.TestCase):
            def run(self, result=None):
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
                try:
                    return super().run(result)
                finally:
                    self._loop.close()
                    asyncio.set_event_loop(None)

            def setUp(self):
                self._loop.run_until_complete(self.asyncSetUp())

            def tearDown(self):
                self._loop.run_until_complete(self.asyncTearDown())

            async def asyncSetUp(self): pass
            async def asyncTearDown(self): pass

            def __getattribute__(self, name):
                val = object.__getattribute__(self, name)
                if name.startswith("test") and asyncio.iscoroutinefunction(val):
                    loop = object.__getattribute__(self, "_loop")
                    def wrapper(fn=val, lp=loop):
                        lp.run_until_complete(fn())
                    return wrapper
                return val


    class TestMyFeature(AsyncTestCase):
        async def test_example(self):
            from p2pd import *
            nic = await Interface()
            self.assertIsNotNone(nic)


    if __name__ == "__main__":
        unittest.main()

Put the file in ``tests/`` and run:

.. parsed-literal::

    python3 -m pytest tests/test_my_feature.py -v

----

Test infrastructure helpers
------------------------------

The test directory contains helper modules used across tests:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Module
     - Purpose
   * - ``tests/stun_server.py``
     - Standalone STUN server for local testing (no network needed).
   * - ``tests/turn_server.py``
     - Standalone TURN server and ``make_fake_nic()`` helper.
   * - ``tests/if_servers.py``
     - Interface-level server helpers.
   * - ``tests/functional/``
     - Multi-machine functional tests (uses SSH for remote execution).
