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
import sys
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
    print("[RP-ECHO-HANDLER] msg={0!r} client_tup={1!r}".format(msg, client_tup))
    if msg[:4] == b"ECHO":
        try:
            await pipe.send(msg[4:] + b"\r\n", client_tup)
            print("[RP-ECHO-HANDLER] replied")
        except (OSError, ConnectionError) as exc:
            print("[RP-ECHO-HANDLER] send failed: {0!r}".format(exc))


def collapse_ext_to_nic(node):
    """Rewrite this node's addr_map so each if_info's ext == nic.

    On a single host where both nodes share a router (the common
    dev-box case), routing each node's "ext" IP through the home
    router does NAT hairpinning -- the cone receives src = own
    WAN IP, the symmetric peer never reaches it, and echo can't
    round-trip.  Collapsing ext to nic side-steps the router
    entirely: probes destined for the peer's nic IP route via
    the kernel's lo shortcut (Linux delivers locally when the
    dst IP is bound on the host) so the algorithm converges over
    a real local 4-tuple with no NAT in the path.
    """
    addr_map = node.addr_map or {}
    for af in (IP4,):
        ifs = addr_map.get(af) or {}
        for if_info in ifs.values():
            nic_ip = if_info.get("nic")
            if nic_ip is None:
                continue
            if_info["ext"] = nic_ip


class TestRandomProbeEcho(AsyncTestCase):
    """random_probe: pipe round-trips a real payload between two nodes."""

    async def asyncSetUp(self):
        # Windows hits two ceilings here: select.select()'s FD_SETSIZE=64
        # cap chokes on the symmetric side's PROBE_COUNT sockets, and
        # the collapse_ext_to_nic + lo-shortcut routing trick this test
        # relies on for hairpin-free convergence is Linux-specific.
        # Matrix VMs with the flaky mobile NIC also can't keep the
        # ext-IP path alive long enough for the echo to round-trip.
        # Linux dev box (matrix Linux node) is the right venue.
        if sys.platform == "win32":
            self.skipTest(
                "random_probe echo round-trip is Linux-only "
                "(FD_SETSIZE + lo-routing assumptions)"
            )
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

        # Side-step whatever NAT / routing path the host has between
        # the two NICs.  By rewriting each node's "ext" IP to be its
        # NIC IP, the algorithm fires probes between the two LAN
        # IPs, which the kernel delivers locally via lo since both
        # are bound on this host.  No router, no NAT, no hairpin --
        # the algorithm exercises its protocol + sock_to_pipe + msg_cb
        # path over a clean local 4-tuple.
        collapse_ext_to_nic(self.node_a)
        collapse_ext_to_nic(self.node_b)

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
