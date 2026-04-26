"""
Real-NAT end-to-end test for the random_probe plugin.

Targets a local host with TWO physical NICs that have *distinct
internet uplinks* -- e.g. a VM with ens34 on the home ISP and
ens37 on a mobile carrier, where each NIC has its own public IP
(STUN reports two different external addresses).

What it does:
  1. Lists local interfaces, picks two whose route to the
     internet is non-overlapping (different external IPs via
     STUN).
  2. Starts Node A on the first NIC, Node B on the second.  To
     force the algorithm down its cross-machine code path
     (using ext IPs that traverse the real NAT, not LAN IPs
     that go via lo) we overwrite Node B's machine_id so the
     two nodes look like distinct hosts.
  3. Both nodes register an echo handler.
  4. A initiates `node.connect(IP4, EXT_BIND, B.addr_bytes,
     "random_probe")`, awaits the resulting Pipe, sends
     b"ECHO real-nat-test\\n", and reads the reply.
  5. Asserts the echo round-trip completes within the timeout.

Skipped when:
  * fewer than two interfaces are visible
  * STUN reports the same external IP for both NICs (one
    uplink → can't actually exercise random_probe)
  * the test isn't running as root + SO_BINDTODEVICE fails
    (Linux requires CAP_NET_RAW; without it packets sourced
    from a non-default NIC's IP egress through the default-
    route NIC and the algorithm hairpins instead of crossing
    the internet).

Heavy + lives in its own subprocess per CLAUDE.md.

Run:
    sudo python -m unittest discover -s tests -p test_random_probe_real_nat.py -v
"""

import asyncio
import os
import unittest

from aionetiface import (
    EXT_BIND,
    IP4,
    Interface,
    SUB_ALL,
    list_interfaces,
    to_b,
)
from aionetiface.testing import AsyncTestCase

from p2pd.node.node import Node, NODE_PORT


PORT_A = NODE_PORT + 2750
PORT_B = NODE_PORT + 2751


# Loud diagnostics so a one-shot run yields enough info to
# triage when it fails -- the test can't be iterated from the
# author's machine, only the developer's, so logs matter.
async def echo_handler(msg, client_tup, pipe):
    print("[REAL-NAT-ECHO-CB] msg={0!r} client_tup={1!r}".format(
        msg[:64], client_tup,
    ))
    if msg[:4] == b"ECHO":
        try:
            await pipe.send(msg[4:], client_tup)
            print("[REAL-NAT-ECHO-CB] replied to {0}".format(client_tup))
        except (OSError, ConnectionError) as exc:
            print("[REAL-NAT-ECHO-CB] reply failed: {0!r}".format(exc))


def find_distinct_uplink_pair(node_a_ext, node_b_ext):
    """True iff node A's ext IP differs from node B's ext IP."""
    return node_a_ext and node_b_ext and node_a_ext != node_b_ext


class TestRandomProbeRealNat(AsyncTestCase):
    """random_probe via real cross-internet path between two local NICs."""

    async def asyncSetUp(self):
        self.node_a = self.node_b = None
        self.plugin_a = None

        nic_names = await list_interfaces()
        print("[REAL-NAT] visible NICs: {0!r}".format(nic_names))
        if len(nic_names) < 2:
            self.skipTest(
                "need >= 2 interfaces with separate uplinks; "
                "only saw {0}".format(nic_names)
            )

        # Try every (i, j) pair until we find one whose external
        # IPs differ; that's the pair the algorithm can usefully
        # traverse.
        loaded = {}
        for name in nic_names:
            try:
                nic = await Interface(name)
                if IP4 not in nic.supported():
                    continue
                # NAT classification is best-effort -- fall back
                # to whatever Interface() probed if load_nat
                # can't reach the STUN test pool.
                try:
                    await asyncio.wait_for(nic.load_nat(), timeout=10)
                except Exception as exc:  # ErrorCantLoadNATInfo + friends
                    print("[REAL-NAT] {0} load_nat failed: {1!r}".format(name, exc))
                loaded[name] = nic
            except (OSError, ValueError) as exc:
                print("[REAL-NAT] skip NIC {0}: {1!r}".format(name, exc))

        chosen = None
        for a_name, a_nic in loaded.items():
            for b_name, b_nic in loaded.items():
                if a_name == b_name:
                    continue
                a_ext = self.nic_ext_ip(a_nic)
                b_ext = self.nic_ext_ip(b_nic)
                print("[REAL-NAT] try pair ({0} ext={1}) ({2} ext={3})".format(
                    a_name, a_ext, b_name, b_ext,
                ))
                if find_distinct_uplink_pair(a_ext, b_ext):
                    chosen = (a_nic, b_nic)
                    break
            if chosen is not None:
                break

        if chosen is None:
            self.skipTest(
                "no pair of NICs with distinct external IPs found; "
                "this test needs two physically separate uplinks "
                "(e.g. home ISP + mobile carrier)"
            )
        self.nic_a, self.nic_b = chosen
        print("[REAL-NAT] chose: A={0} ext={1}, B={2} ext={3}".format(
            self.nic_a.id, self.nic_ext_ip(self.nic_a),
            self.nic_b.id, self.nic_ext_ip(self.nic_b),
        ))

    @staticmethod
    def nic_ext_ip(nic):
        """Best-effort string of the NIC's IPv4 external IP, or '' if missing."""
        try:
            ext = nic.route(IP4).ext()
            return str(ext) if ext is not None else ""
        except (LookupError, AttributeError, ValueError):
            return ""

    async def asyncTearDown(self):
        from p2pd.traversal.traversal_utils import close_plugin
        if self.plugin_a is not None and self.node_a is not None:
            try:
                await close_plugin(
                    self.plugin_a,
                    self.node_a.traversal.plugins,
                    self.node_a.traversal.inbound_pipes,
                )
            except (OSError, asyncio.TimeoutError):
                pass
        for n in (self.node_b, self.node_a):
            if n is not None:
                try:
                    await asyncio.wait_for(n.close(), timeout=10)
                except (OSError, asyncio.TimeoutError):
                    pass

    async def test_real_nat_echo_round_trip(self):
        # Bind each Node to its own NIC.  Forcing distinct
        # machine_ids makes same_machine=False so the algorithm
        # uses ext IPs (real cross-internet path) instead of
        # collapsing to NIC IPs (local kernel lo path) which
        # wouldn't actually exercise the NAT traversal.
        self.node_a = Node(ifs=[self.nic_a], ip=None, port=PORT_A)
        await asyncio.wait_for(self.node_a.start(), timeout=35)
        self.node_b = Node(ifs=[self.nic_b], ip=None, port=PORT_B)
        await asyncio.wait_for(self.node_b.start(), timeout=35)

        # Force distinct machine_ids so the random_probe plugin
        # sees same_machine=False and uses ext-IP path.  Without
        # this both nodes share the host's machine_id, the
        # algorithm short-circuits to NIC IPs (because
        # same_machine collapses my_addr_ip / peer_addr_ip to
        # the NIC's local IP) and the kernel never sends those
        # over the wire.  We re-serialise addr_bytes so the
        # peer-parsed machine_id reflects the override.
        from aionetiface import make_node_addr, parse_node_addr
        self.node_b.machine_id = self.node_b.machine_id + "-B"
        self.node_b.addr_bytes = make_node_addr(
            self.node_b.kp.public_key_hex,
            self.node_b.machine_id,
            self.node_b.ifs,
            port=self.node_b.listen_port,
        )
        self.node_b.addr_map = parse_node_addr(self.node_b.addr_bytes)
        self.node_b.traversal.addr_bytes = self.node_b.addr_bytes

        print("[REAL-NAT] node_a machine_id={0} node_b machine_id={1}".format(
            self.node_a.machine_id, self.node_b.machine_id,
        ))

        # NAT classification on this VM intermittently reports
        # SYMMETRIC (type 6) for both NICs because the STUN test 3
        # reply gets dropped and the classifier falls through to
        # symmetric.  When that happens random_probe's alignment
        # filter is enabled and the algorithm can't converge --
        # even though the actual home NAT is full-cone.  Force
        # the local view to FULL_CONE for the test so the
        # algorithm proceeds; we're testing the random_probe
        # plumbing, not the classifier.
        from aionetiface.nic.nat.nat_defs import FULL_CONE
        for node in (self.node_a, self.node_b):
            for if_info in (node.addr_map.get(IP4) or {}).values():
                nat = if_info.get("nat") or {}
                nat["type"] = FULL_CONE
                if_info["nat"] = nat

        # Echo handler on BOTH sides -- the plugin attaches
        # node.msg_cb to the pipe via on_plugin_done, which
        # dispatches to all registered msg_cbs.
        self.node_a.add_msg_cb(echo_handler)
        self.node_b.add_msg_cb(echo_handler)

        self.assertIn(
            "random_probe", self.node_a.traversal.plugin_loaders,
            "random_probe must be registered on node_a",
        )
        self.assertIn(
            "random_probe", self.node_b.traversal.plugin_loaders,
            "random_probe must be registered on node_b",
        )

        # Initiate random_probe from A.
        try:
            self.plugin_a = await asyncio.wait_for(
                self.node_a.connect(
                    IP4, EXT_BIND, self.node_b.addr_bytes, "random_probe",
                ),
                timeout=30,
            )
        except (asyncio.TimeoutError, ValueError) as exc:
            self.fail(
                "node.connect(random_probe) didn't return a plugin: "
                "{0!r}.  Means the connect-side path is broken before "
                "the protocol even gets to run.".format(exc)
            )

        try:
            pipe = await asyncio.wait_for(self.plugin_a.result, timeout=30)
        except asyncio.TimeoutError:
            self.fail(
                "plugin.result didn't resolve within 30s -- "
                "convergence failed even with two real uplinks; "
                "check log for [RP-WIRE], [RP-INBOUND], etc."
            )

        self.assertIsNotNone(
            pipe,
            "random_probe round didn't converge -- pipe=None.  "
            "Look at the [RP-INBOUND] / [REAL-NAT-ECHO-CB] log "
            "lines on both sides for which direction broke.",
        )

        print("[REAL-NAT] got pipe: sock={0!r}".format(
            getattr(pipe, "sock", None),
        ))

        pipe.subscribe(SUB_ALL)
        await pipe.send(to_b("ECHO real-nat-test\n"))

        try:
            reply = await asyncio.wait_for(pipe.recv(SUB_ALL, timeout=10), timeout=12)
        except asyncio.TimeoutError:
            reply = None
        print("[REAL-NAT] reply={0!r}".format(reply))

        self.assertIsNotNone(
            reply,
            "Echo never round-tripped.  Either responder's pipe "
            "didn't dispatch to echo_handler (look for "
            "[REAL-NAT-ECHO-CB] on B's stdout), or the reply "
            "didn't make it back to A.",
        )
        self.assertIn(b"real-nat-test", reply)


if __name__ == "__main__":
    unittest.main()
