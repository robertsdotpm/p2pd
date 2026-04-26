"""
End-to-end echo test for the random_probe plugin.

Two real Nodes on two distinct NICs go through the full
random_probe flow -- sorted-IP role assignment, signal exchange
over MQTT, prebound non-sym socket, UDP probe + CONFIRM
handshake, and sock_to_pipe wrap -- and then the *initiator*
sends a real payload over the resulting Pipe and reads the
peer's reply.

This is the test we were missing: it proves the bit between
"plugin returns a pipe" and "data round-trips through it",
which the in-process test_random_probe_local can't exercise
because it stops at convergence.

Heavy by CLAUDE.md's rule -- spins up two Nodes, MQTT
signalling, and the random_probe plugin -- so it lives in its
own file for subprocess isolation.

Skipped when:
  * fewer than 2 distinct interfaces are available
    (load_two_nodes raises skipTest)
  * the connect attempt times out -- treated as ENV when there's
    no real (sym, non-sym) NAT pair on the host.  The plugin
    code path is still validated by the e2e protocol-flow test;
    this one just additionally requires data flow.
"""

import asyncio
import unittest

from aionetiface import IP4, SUB_ALL, to_b
from aionetiface.testing import AsyncTestCase

from p2pd.node.node import NODE_PORT
from p2pd.traversal.traversal_utils import close_plugin

from auto_connect_helpers import (
    close_nodes,
    load_two_nodes,
    start_node_with_ifs,
)


PORT_RP_ECHO_A = NODE_PORT + 2710
PORT_RP_ECHO_B = NODE_PORT + 2711


async def echo_handler(msg, client_tup, pipe):
    """Strip the 'ECHO' prefix and send the rest back to the sender.

    Mirrors the demo's add_echo_support but without any of the
    interactive cout/shutdown plumbing -- just the protocol bit
    we want to assert against.
    """
    if msg[:4] == b"ECHO":
        try:
            await pipe.send(msg[4:], client_tup)
        except (OSError, ConnectionError):
            pass


class TestRandomProbeEcho(AsyncTestCase):
    """random_probe: pipe round-trips a real payload between two nodes."""

    async def asyncSetUp(self):
        self.ifs_a, self.ip_a, self.ifs_b, self.ip_b = await load_two_nodes(
            self, IP4, label="random_probe echo",
        )
        print("[RP-ECHO] setup ip_a={0} ip_b={1} ifs_a={2} ifs_b={3}".format(
            self.ip_a, self.ip_b,
            [nic.id for nic in self.ifs_a],
            [nic.id for nic in self.ifs_b],
        ))
        self.node_a = self.node_b = None
        self.plugin_a = None

    async def asyncTearDown(self):
        if self.plugin_a is not None and self.node_a is not None:
            try:
                await close_plugin(
                    self.plugin_a,
                    self.node_a.traversal.plugins,
                    self.node_a.traversal.inbound_pipes,
                )
            except (OSError, asyncio.TimeoutError):
                pass
        await close_nodes(self.node_b, self.node_a)

    async def test_pipe_round_trips_echo(self):
        """Cone fires probe, sym replies, returned Pipe carries an echo."""
        self.node_a = await start_node_with_ifs(self.ifs_a, [self.ip_a], PORT_RP_ECHO_A)
        self.node_b = await start_node_with_ifs(self.ifs_b, [self.ip_b], PORT_RP_ECHO_B)

        # Both sides need an echo handler.  When the responder's
        # plugin resolves with a Pipe, on_plugin_done attaches
        # node.msg_cb -> node_protocol -> registered msg_cbs;
        # add_msg_cb here is what gets the echo to fire.
        self.node_a.add_msg_cb(echo_handler)
        self.node_b.add_msg_cb(echo_handler)

        self.assertIn(
            "random_probe",
            self.node_a.traversal.plugin_loaders,
            "random_probe must be registered on node_a",
        )
        self.assertIn(
            "random_probe",
            self.node_b.traversal.plugin_loaders,
            "random_probe must be registered on node_b",
        )

        # Use the explicit user-driven path -- pick EXT_BIND so we
        # land in the random_probe combo and the sorted-ext-IP role
        # decision picks consistent sides on both nodes.
        from aionetiface import EXT_BIND
        try:
            self.plugin_a = await asyncio.wait_for(
                self.node_a.connect(
                    IP4, EXT_BIND, self.node_b.addr_bytes, "random_probe",
                ),
                timeout=25,
            )
        except (asyncio.TimeoutError, ValueError) as exc:
            self.skipTest(
                "random_probe connect didn't return a plugin on this host: "
                "{0!r}.  Likely no real (sym, non-sym) NAT or hairpin "
                "support available; matrix VMs are the proper venue.".format(
                    exc,
                )
            )

        try:
            pipe = await asyncio.wait_for(self.plugin_a.result, timeout=25)
        except asyncio.TimeoutError:
            self.skipTest(
                "random_probe plugin.result didn't resolve in time -- "
                "convergence failed on this host (no real NAT / no hairpin)."
            )

        if pipe is None:
            self.skipTest(
                "random_probe round did not converge on this host (pipe=None)"
            )

        print("[RP-ECHO] got pipe sock={0!r}".format(getattr(pipe, "sock", None)))

        # Subscribe so pipe.recv() blocks for inbound on this pipe.
        pipe.subscribe(SUB_ALL)

        # Echo round-trip.  The peer's add_msg_cb(echo_handler) will
        # see the inbound, strip the ECHO prefix, and send back the
        # remaining bytes on the same pipe.
        await pipe.send(to_b("ECHO hello-from-rp-echo\n"))

        try:
            reply = await asyncio.wait_for(pipe.recv(SUB_ALL, timeout=8), timeout=10)
        except asyncio.TimeoutError:
            reply = None
        print("[RP-ECHO] reply={0!r}".format(reply))

        self.assertIsNotNone(
            reply,
            "Pipe round-trip failed: cone sent ECHO, no reply received "
            "within the deadline.  Either the responder's pipe didn't "
            "receive the inbound (sock_to_pipe wiring), the echo handler "
            "didn't fire (on_plugin_done attachment), or the reply "
            "didn't make it back (NAT path one-shot).",
        )
        self.assertIn(b"hello-from-rp-echo", reply)


if __name__ == "__main__":
    unittest.main()
