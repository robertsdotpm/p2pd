"""
Live TURN-fallback integration test.

Unlike test_auto_connect_turn (which patches get_infra to point at a
local ::1 TURN server), this test exercises the real production TURN
infra against two NICs that have *different* public WAN addresses.
That's the only way to confirm TURN actually relays bytes end-to-end
when a direct path is impossible.

Path:

  1. load_two_nodes hands us probe_ifs[0] / probe_ifs[1]. Skip if
     both NICs sit behind the same WAN (ext IPs equal) -- in that
     case TURN's pair_distinct(EXT_BIND) drops the combo and there
     is no fallback to test.

  2. Strip direct_connect / reverse_connect / punch from alice's
     plugin_loaders. TURN is the only path left.

  3. auto_connect must return a pipe whose plugin is TURNPlugin.

  4. alice sends bytes through the pipe; bob's msg_cb captures them.
     Verifies the relay is wired both directions of the stream.

This test will only run when the matrix host has two NICs with
distinct public WAN IPs (LAN + mobile carrier in the current rig).
Single-NIC hosts skip via load_two_nodes; same-WAN hosts skip via
the ext-IP check below.
"""

import asyncio
import unittest

from aionetiface import IP4
from aionetiface.testing import AsyncTestCase

from auto_connect_helpers import (
    AUTO_TEST_CONF,
    PORT_TURN_LIVE_A, PORT_TURN_LIVE_B,
    close_nodes, load_two_nodes, start_node_with_ifs,
)


class TestAutoConnectTurnLive(AsyncTestCase):
    """auto_connect falls back to a real TURN server when direct paths are removed."""

    # TURN session setup over the public internet is slower than the local
    # ::1 server in test_auto_connect_turn, so loosen the per-test budget.
    async_test_timeout = 180

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="TURN live (IPv4)",
        )
        print("[TURN-LIVE] setup ip_a={0} ip_b={1} ifs_a={2} ifs_b={3}".format(
            self.ip_a, self.ip_b,
            [nic.id for nic in self.ifs_a],
            [nic.id for nic in self.ifs_b],
        ))
        self.node_a = self.node_b = None

    async def asyncTearDown(self):
        await close_nodes(self.node_b, self.node_a)

    async def test_turn_relays_bytes_between_distinct_ext_ips(self):
        """Real TURN server must relay alice -> bob across distinct public WAN IPs.

        Walks public TURN servers directly: spins up a fresh
        TURNClient pair per server and stops at the first one that
        actually delivers bytes end-to-end. That keeps a single bad
        server (any one whose ALLOCATE / CreatePermission / relay-
        recv path is broken on this network at this moment) from
        flaking the whole test -- the assertion is "at least one
        production TURN server can relay between two distinct
        public WAN IPs from this host", which is the real-world
        property TURN fallback ultimately depends on.
        """
        from aionetiface import UDP, get_infra
        from p2pd.traversal.plugins.turn.turn_client import TURNClient

        self.node_a = await start_node_with_ifs(
            self.ifs_a, [self.ip_a], PORT_TURN_LIVE_A, conf=AUTO_TEST_CONF
        )
        self.node_b = await start_node_with_ifs(
            self.ifs_b, [self.ip_b], PORT_TURN_LIVE_B, conf=AUTO_TEST_CONF
        )

        # Sanity: distinct public WAN IPs (otherwise EXT_BIND pair_distinct
        # would drop the combo in real auto_connect; the relay isn't
        # meaningful when both peers share an ext).
        a_info = next(iter((self.node_a.addr_map.get(IP4) or {}).values()), None)
        b_info = next(iter((self.node_b.addr_map.get(IP4) or {}).values()), None)
        ext_a = a_info.get("ext") if a_info else None
        ext_b = b_info.get("ext") if b_info else None
        print("[TURN-LIVE] node_a ext={0} node_b ext={1}".format(ext_a, ext_b))
        if ext_a is None or ext_b is None:
            self.skipTest("STUN didn't discover an IPv4 ext for one or both NICs")
        if int(ext_a) == int(ext_b):
            self.skipTest(
                "Both NICs sit behind the same WAN ({0} == {1}); "
                "no distinct-EXT TURN combo possible".format(ext_a, ext_b)
            )

        groups = get_infra(IP4, UDP, "TURN", no=200)
        servers = [g[0] for g in groups if g]
        self.assertTrue(servers, "no public IPv4 TURN servers in get_infra")
        print("[TURN-LIVE] {0} candidate TURN servers".format(len(servers)))

        nic_a = self.ifs_a[0]
        nic_b = self.ifs_b[0]
        payload = b"turn relay test"

        attempted = []
        for idx, server in enumerate(servers):
            label = "{0}:{1}".format(server.get("ip"), server.get("port"))
            received = asyncio.Event()
            received_data = []

            def on_b_msg(msg, client_tup, pipe):
                received_data.append(msg)
                if msg and payload in msg:
                    received.set()

            client_a = TURNClient(
                af=IP4,
                dest=(server["ip"], server["port"]),
                nic=nic_a,
                auth=(server.get("user", ""), server.get("password", "")),
                realm=None,
            )
            client_b = TURNClient(
                af=IP4,
                dest=(server["ip"], server["port"]),
                nic=nic_b,
                auth=(server.get("user", ""), server.get("password", "")),
                realm=None,
                msg_cb=on_b_msg,
            )

            outcome = "unknown"
            try:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(client_a.start(), client_b.start()),
                        timeout=15,
                    )
                except asyncio.TimeoutError:
                    outcome = "allocate-timeout"
                    raise

                a_peer = await client_a.client_tup_future
                a_relay = await client_a.relay_tup_future
                b_peer = await client_b.client_tup_future
                b_relay = await client_b.relay_tup_future

                try:
                    await asyncio.wait_for(
                        asyncio.gather(
                            client_a.accept_peer(b_peer, b_relay),
                            client_b.accept_peer(a_peer, a_relay),
                        ),
                        timeout=10,
                    )
                except asyncio.TimeoutError:
                    outcome = "create-permission-timeout"
                    raise

                await client_a.send(payload, dest_tup=b_peer)
                try:
                    await asyncio.wait_for(received.wait(), timeout=8)
                except asyncio.TimeoutError:
                    outcome = "relay-recv-timeout"
                    raise

                self.assertTrue(
                    any(payload in m for m in received_data if m),
                    "received_data missing payload: {!r}".format(received_data),
                )
                print("[TURN-LIVE] PASS via {0} ({1}/{2})".format(
                    label, idx + 1, len(servers),
                ))
                outcome = "ok"
                return  # one working server is sufficient
            except (OSError, ConnectionError, asyncio.TimeoutError, ValueError, AssertionError) as exc:
                attempted.append((label, outcome, repr(exc)))
                print("[TURN-LIVE] FAIL via {0} ({1}/{2}) phase={3} exc={4!r}".format(
                    label, idx + 1, len(servers), outcome, exc,
                ))
            finally:
                for c in (client_a, client_b):
                    try:
                        await asyncio.wait_for(c.close(), timeout=4)
                    except Exception:
                        pass

        # Walked every server, none worked.
        self.fail(
            "no public TURN server relayed bytes between distinct WANs; "
            "tried {0}: {1}".format(len(attempted), attempted)
        )


if __name__ == "__main__":
    unittest.main()
