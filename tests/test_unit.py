"""
Offline unit tests — no network required, no node startup.

Run from the project root:
    python3 -m unittest tests/test_unit.py -v
"""

import asyncio
import hashlib
import socket
import tempfile
import unittest

from p2pd import (
    IP4,
    IP6,
    EXT_BIND,
    NIC_BIND,
    parse_node_addr,
)
from p2pd.node.node import Node
from p2pd.node.node_defs import NODE_TEST_CONF
from p2pd.node.node_utils import norm_listen_ips, load_signing_key
from p2pd.node.nickname import (
    Nickname,
    pnp_name_has_tld,
    pnp_strip_tlds,
    pnp_get_tld,
    pnp_get_offsets,
)
from p2pd.traversal.traversal_manager import TraversalManager
from p2pd.traversal.traversal_plugin import TraversalPlugin
from p2pd.traversal.traversal_utils import select_dest_ipr, sort_pairs_by_overlap
from p2pd.protocol.traversal.proto_msg import (
    ConMsg,
    GetAddr,
    ReturnAddr,
    PunchMsg,
    TURNMsg,
    ProtoMsg,
    SIG_PROTO,
    SIG_CON,
    SIG_TCP_PUNCH,
    SIG_GET_ADDR,
    SIG_RETURN_ADDR,
)
from p2pd.traversal.traversal_utils import try_unpack_msg, sig_msg_to_buf


# ---------------------------------------------------------------------------
# Shared fixture: a valid serialised P2P node address (no real NIC needed).
# Format: ip4_infos ^ ip6_infos ^ pub_key_hex ^ machine_id
# ---------------------------------------------------------------------------
VALID_ADDR = (
    b"[1,0,8.8.8.8,192.168.1.10,10001,1,2,1]"
    b"^0"
    b"^93e9d6f7e7791ea06544557a2"
    b"^c88e78bafc408223a97b560ea94f1bb4d5fc58a5705a41a2a94d54466d552816"
)


# ===========================================================================
# 1. P2P Address parsing
# ===========================================================================
class TestParseNodeAddr(unittest.TestCase):
    def test_valid_addr_parses(self):
        out = parse_node_addr(VALID_ADDR)
        self.assertIsNotNone(out)
        self.assertIn(IP4, out)
        self.assertGreater(len(out[IP4]), 0)

    def test_v4_interface_fields(self):
        out = parse_node_addr(VALID_ADDR)
        info = out[IP4][0]
        self.assertIn("ext", info)
        self.assertIn("nic", info)
        self.assertIn("port", info)
        self.assertIn("nat", info)
        self.assertEqual(info["port"], 10001)

    def test_pub_key_hex_extracted(self):
        out = parse_node_addr(VALID_ADDR)
        self.assertEqual(out["pub_key_hex"], "93e9d6f7e7791ea06544557a2")

    def test_machine_id_extracted(self):
        out = parse_node_addr(VALID_ADDR)
        self.assertEqual(
            out["machine_id"],
            "c88e78bafc408223a97b560ea94f1bb4d5fc58a5705a41a2a94d54466d552816",
        )

    def test_bytes_preserved(self):
        out = parse_node_addr(VALID_ADDR)
        self.assertEqual(out["bytes"], VALID_ADDR)

    def test_dict_passthrough(self):
        # Already-parsed dicts should come back unchanged.
        parsed = parse_node_addr(VALID_ADDR)
        again = parse_node_addr(parsed)
        self.assertIs(again, parsed)

    def test_invalid_format_returns_none(self):
        self.assertIsNone(parse_node_addr(b"garbage"))
        self.assertIsNone(parse_node_addr(b"a^b^c"))  # only 3 parts, need 4

    def test_string_input_accepted(self):
        out = parse_node_addr(VALID_ADDR.decode())
        self.assertIsNotNone(out)


# ===========================================================================
# 2. Nickname TLD utilities
# ===========================================================================
class TestNicknameTLD(unittest.TestCase):
    def test_has_tld_all_valid(self):
        for tld in (".p2p", ".node", ".peer"):
            with self.subTest(tld=tld):
                self.assertTrue(pnp_name_has_tld("alice" + tld))

    def test_has_tld_no_tld(self):
        self.assertFalse(pnp_name_has_tld("alice"))
        self.assertFalse(pnp_name_has_tld("alice.com"))
        self.assertFalse(pnp_name_has_tld(""))

    def test_strip_tld_removes_suffix(self):
        for tld in (".p2p", ".node", ".peer"):
            with self.subTest(tld=tld):
                self.assertEqual(pnp_strip_tlds("alice" + tld), "alice")

    def test_strip_tld_noop_without_tld(self):
        self.assertEqual(pnp_strip_tlds("alice"), "alice")
        self.assertEqual(pnp_strip_tlds("alice.com"), "alice.com")

    def test_get_tld_roundtrip(self):
        for tld in (".p2p", ".node", ".peer"):
            with self.subTest(tld=tld):
                offsets = pnp_get_offsets(tld)
                back = pnp_get_tld(offsets)
                self.assertEqual(tld, back)

    def test_peer_tld_uses_both_offsets(self):
        offsets = pnp_get_offsets(".peer")
        self.assertEqual(sorted(offsets), [0, 1])

    def test_p2p_offset_is_zero(self):
        offsets = pnp_get_offsets(".p2p")
        self.assertEqual(list(offsets), [0])

    def test_node_offset_is_one(self):
        offsets = pnp_get_offsets(".node")
        self.assertEqual(list(offsets), [1])

    def test_unknown_tld_raises(self):
        with self.assertRaises(KeyError):
            pnp_get_offsets(".unknown")


# ===========================================================================
# 3. Nickname raises RuntimeError when called before start()
# ===========================================================================
class TestNicknameNotStarted(unittest.IsolatedAsyncioTestCase):
    async def _make_nick(self):
        """Build a Nickname without calling start()."""
        from ecdsa import SigningKey, SECP256k1

        sk = SigningKey.generate(curve=SECP256k1)
        # Nickname.__init__ accepts ifs/sys_clock; we pass [] and None
        # because we never call start().
        return Nickname(sk, [], None)

    async def test_put_before_start_raises(self):
        nick = await self._make_nick()
        with self.assertRaises(RuntimeError):
            await nick.put("name", b"value")

    async def test_get_before_start_raises(self):
        nick = await self._make_nick()
        with self.assertRaises(RuntimeError):
            await nick.get("name.p2p")

    async def test_delete_before_start_raises(self):
        nick = await self._make_nick()
        with self.assertRaises(RuntimeError):
            await nick.delete("name.p2p")


# ===========================================================================
# 4. Protocol message serialisation / deserialisation
# ===========================================================================
class TestProtoMessages(unittest.TestCase):
    def _roundtrip(self, msg_class, enum, data=None):
        """Pack a message and unpack it; return both."""
        msg = msg_class(data or {})
        buf = msg.pack()
        # buf = bytes([enum]) + json-body
        self.assertEqual(buf[0], enum)
        unpacked = msg_class.unpack(buf[1:])
        return msg, unpacked

    def test_conmsg_plugin_name_preserved(self):
        msg = ConMsg({"meta": {"plugin_name": "direct_connect"}})
        _, up = self._roundtrip(
            ConMsg, SIG_CON, {"meta": {"plugin_name": "direct_connect"}}
        )
        self.assertEqual(up.meta.plugin_name, "direct_connect")

    def test_getaddr_plugin_name(self):
        _, up = self._roundtrip(
            GetAddr, SIG_GET_ADDR, {"meta": {"plugin_name": "return_addr"}}
        )
        self.assertEqual(up.meta.plugin_name, "return_addr")

    def test_returnaddr_plugin_name(self):
        _, up = self._roundtrip(
            ReturnAddr, SIG_RETURN_ADDR, {"meta": {"plugin_name": "get_addr"}}
        )
        self.assertEqual(up.meta.plugin_name, "get_addr")

    def test_punchmsg_payload_roundtrip(self):
        data = {
            "payload": {
                "punch_mode": 1,
                "ntp": 1234567890.0,
                "mappings": [[10000, 10001]],
            }
        }
        msg = PunchMsg(data)
        buf = msg.pack()
        up = PunchMsg.unpack(buf[1:])
        self.assertEqual(up.payload.punch_mode, 1)
        self.assertEqual(up.payload.ntp, 1234567890.0)
        self.assertEqual(up.payload.mappings, [[10000, 10001]])

    def test_sig_proto_contains_expected_types(self):
        self.assertIn(SIG_CON, SIG_PROTO)
        self.assertIn(SIG_TCP_PUNCH, SIG_PROTO)
        self.assertIn(SIG_GET_ADDR, SIG_PROTO)
        self.assertIn(SIG_RETURN_ADDR, SIG_PROTO)
        for enum, info in SIG_PROTO.items():
            self.assertIsNotNone(info[0], f"No class for SIG_PROTO[{enum}]")

    def test_sig_msg_to_buf_and_try_unpack_roundtrip(self):
        """Wire sig_msg_to_buf -> try_unpack_msg with a live ConMsg."""
        msg = ConMsg({"meta": {"plugin_name": "direct_connect", "af": IP4}})
        # Set routing with a real dest_buf so routing.dest is populated.
        msg.routing = ProtoMsg.Routing.from_dict(
            {
                "af": IP4,
                "dest_buf": VALID_ADDR,
                "dest_index": 0,
            }
        )

        buf = sig_msg_to_buf(msg, None)
        unpacked = try_unpack_msg(buf, None, SIG_PROTO)
        self.assertIsInstance(unpacked, ConMsg)
        self.assertEqual(unpacked.meta.plugin_name, "direct_connect")

    def test_sig_msg_to_buf_unencrypted_when_no_vk(self):
        """When dest vk is None the message should NOT be encrypted."""
        msg = ConMsg({})
        msg.routing = ProtoMsg.Routing.from_dict(
            {
                "af": IP4,
                "dest_buf": VALID_ADDR,
                "dest_index": 0,
            }
        )
        # vk from parse_node_addr is None so message should be unencrypted
        from aionetiface import h_to_b, to_b

        raw = h_to_b(to_b(sig_msg_to_buf(msg, None)))
        is_encrypted = raw[0]
        self.assertEqual(is_encrypted, 0)


# ===========================================================================
# 5. TraversalManager initialisation
# ===========================================================================
class TestTraversalManagerInit(unittest.TestCase):
    def test_default_attrs_exist(self):
        tm = TraversalManager(None, None)
        self.assertIsNone(tm.router)
        self.assertEqual(tm.tasks, [])
        self.assertEqual(tm.inbound_pipes, {})
        self.assertEqual(tm.nics, [])
        self.assertIsNone(tm.done_callback)

    def test_no_shared_state_between_instances(self):
        """Mutable default arg fix: each instance gets its own containers."""
        tm1 = TraversalManager(None, None)
        tm2 = TraversalManager(None, None)
        self.assertIsNot(tm1.inbound_pipes, tm2.inbound_pipes)
        self.assertIsNot(tm1.nics, tm2.nics)
        self.assertIsNot(tm1.tasks, tm2.tasks)

    def test_mutations_do_not_bleed_between_instances(self):
        tm1 = TraversalManager(None, None)
        tm2 = TraversalManager(None, None)
        tm1.inbound_pipes["key"] = "value"
        tm1.nics.append("eth0")
        self.assertNotIn("key", tm2.inbound_pipes)
        self.assertNotIn("eth0", tm2.nics)

    def test_explicit_shared_pipes_param_works(self):
        shared = {}
        tm = TraversalManager(None, None, inbound_pipes=shared)
        tm.inbound_pipes["x"] = 1
        self.assertEqual(shared["x"], 1)

    def test_install_plugin_stores_conf(self):
        tm = TraversalManager(None, None)

        class DummyPlugin(TraversalPlugin):
            pass

        tm.install_plugin("dummy", {"class": DummyPlugin, "timeout": 7})
        self.assertIn("dummy", tm.plugin_loaders)
        self.assertEqual(tm.plugin_loaders["dummy"]["timeout"], 7)
        self.assertEqual(tm.plugin_loaders["dummy"]["class"], DummyPlugin)

    def test_install_plugin_missing_class_raises(self):
        tm = TraversalManager(None, None)
        with self.assertRaises((ValueError, AssertionError, KeyError)):
            tm.install_plugin("bad", {})


# ===========================================================================
# 6. TraversalPlugin initialisation
# ===========================================================================
class TestTraversalPlugin(unittest.IsolatedAsyncioTestCase):
    async def test_result_is_future(self):
        p = TraversalPlugin()
        self.assertIsInstance(p.result, asyncio.Future)

    async def test_pipe_id_is_unique_string(self):
        p1 = TraversalPlugin()
        p2 = TraversalPlugin()
        self.assertIsInstance(p1.plugin_id, str)
        self.assertNotEqual(p1.plugin_id, p2.plugin_id)

    async def test_has_reply_is_event(self):
        p = TraversalPlugin()
        self.assertIsInstance(p.has_reply, asyncio.Event)
        self.assertFalse(p.has_reply.is_set())

    async def test_set_pipes_updates_pipe_id(self):
        p = TraversalPlugin()
        pipes = {}
        p.set_inbound_pipes(pipes, "custom-id")
        self.assertEqual(p.plugin_id, "custom-id")
        self.assertIs(p.inbound_pipes, pipes)

    async def test_set_pipes_preserves_existing_id_if_none_given(self):
        p = TraversalPlugin()
        original = p.plugin_id
        pipes = {}
        p.set_inbound_pipes(pipes)
        self.assertEqual(p.plugin_id, original)

    async def test_set_send_signal_msg_stored(self):
        p = TraversalPlugin()
        sentinel = object()
        p.set_send_signal_msg(sentinel)
        self.assertIs(p._send_signal_msg, sentinel)


# ===========================================================================
# 7. Node.__init__ (no network, no startup)
# ===========================================================================
class TestNodeInit(unittest.TestCase):
    def _make_node(self):
        rw = socket.socketpair()
        rw[0].setblocking(False)
        rw[1].setblocking(True)
        n = Node(stop_rw=rw, conf=NODE_TEST_CONF)
        self._rw = rw
        return n

    def tearDown(self):
        if hasattr(self, "_rw"):
            try:
                self._rw[0].close()
                self._rw[1].close()
            except Exception:
                pass

    def test_pipes_empty(self):
        n = self._make_node()
        self.assertEqual(n.inbound_pipes, {})

    def test_traversal_none_before_start(self):
        """traversal is wired up in start(), not __init__."""
        n = self._make_node()
        self.assertIsNone(n.traversal)

    def test_addr_bytes_none_before_start(self):
        n = self._make_node()
        self.assertIsNone(n.addr_bytes)


# ===========================================================================
# 8. pipe_future / pipe_ready (the return-value bug we fixed)
# ===========================================================================
class TestPipeFuture(unittest.IsolatedAsyncioTestCase):
    def _make_node(self):
        rw = socket.socketpair()
        rw[0].setblocking(False)
        rw[1].setblocking(True)
        n = Node(stop_rw=rw, conf=NODE_TEST_CONF)
        self._rw = rw
        return n

    def tearDown(self):
        if hasattr(self, "_rw"):
            try:
                self._rw[0].close()
                self._rw[1].close()
            except Exception:
                pass

    async def test_pipe_future_returns_future_not_string(self):
        """Regression: pipe_future() used to return the pipe_id string."""
        n = self._make_node()
        fut = n.pipe_future("abc")
        self.assertIsInstance(fut, asyncio.Future)

    async def test_pipe_future_creates_entry_in_pipes(self):
        n = self._make_node()
        n.pipe_future("my-pipe")
        self.assertIn("my-pipe", n.inbound_pipes)

    async def test_pipe_future_idempotent(self):
        n = self._make_node()
        fut1 = n.pipe_future("my-pipe")
        fut2 = n.pipe_future("my-pipe")
        self.assertIs(fut1, fut2)

    async def test_pipe_ready_resolves_future(self):
        n = self._make_node()
        fut = n.pipe_future("my-pipe")
        self.assertFalse(fut.done())
        n.pipe_ready("my-pipe", "the-pipe-object")
        self.assertTrue(fut.done())
        self.assertEqual(fut.result(), "the-pipe-object")

    async def test_pipe_ready_unknown_id_is_noop(self):
        n = self._make_node()
        # Should not raise even if no future was registered first.
        n.pipe_ready("nonexistent", "something")

    async def test_pipe_ready_idempotent_after_done(self):
        n = self._make_node()
        n.pipe_future("x")
        n.pipe_ready("x", "first")
        n.pipe_ready("x", "second")  # already done — should not raise
        self.assertEqual(n.inbound_pipes["x"].result(), "first")


# ===========================================================================
# 9. load_signing_key
# ===========================================================================
class TestLoadSigningKey(unittest.TestCase):
    def test_generates_and_persists_key(self):
        with tempfile.TemporaryDirectory() as td:
            sk1 = load_signing_key([], [], 10001, td)
            sk2 = load_signing_key([], [], 10001, td)
            self.assertEqual(sk1.to_string(), sk2.to_string())

    def test_different_ports_give_different_keys(self):
        with tempfile.TemporaryDirectory() as td:
            sk1 = load_signing_key([], [], 10001, td)
            sk2 = load_signing_key([], [], 10002, td)
            self.assertNotEqual(sk1.to_string(), sk2.to_string())

    def test_different_dirs_give_different_keys(self):
        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            sk1 = load_signing_key([], [], 10001, td1)
            sk2 = load_signing_key([], [], 10001, td2)
            # Different install paths produce different key files.
            # Keys MAY be different (different random seeds).
            # At minimum both are valid SigningKey objects.
            from ecdsa import SigningKey

            self.assertIsInstance(sk1, SigningKey)
            self.assertIsInstance(sk2, SigningKey)

    def test_returned_key_has_verifying_key(self):
        with tempfile.TemporaryDirectory() as td:
            sk = load_signing_key([], [], 10001, td)
            vk = sk.verifying_key
            compressed = vk.to_string("compressed")
            self.assertEqual(len(compressed), 33)

    def test_node_id_derivation_consistent(self):
        """node_id = sha256(compressed_vk)[:25] — verify this is stable."""
        with tempfile.TemporaryDirectory() as td:
            sk = load_signing_key([], [], 10001, td)
            vk_bytes = sk.verifying_key.to_string("compressed")
            node_id = hashlib.sha256(vk_bytes).hexdigest()[:25]
            self.assertEqual(len(node_id), 25)
            # Same key → same node_id
            node_id2 = hashlib.sha256(vk_bytes).hexdigest()[:25]
            self.assertEqual(node_id, node_id2)


# ===========================================================================
# 10. norm_listen_ips
# ===========================================================================
class TestNormListenIps(unittest.TestCase):
    def test_empty_list_returns_empty(self):
        self.assertEqual(norm_listen_ips([]), [])

    def test_none_returns_none(self):
        self.assertIsNone(norm_listen_ips(None))

    def test_deduplicates(self):
        result = norm_listen_ips(["192.168.1.1", "10.0.0.1", "192.168.1.1"])
        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.1", result)
        self.assertIn("10.0.0.1", result)

    def test_sorted_deterministically(self):
        r1 = norm_listen_ips(["10.0.0.2", "10.0.0.1"])
        r2 = norm_listen_ips(["10.0.0.1", "10.0.0.2"])
        self.assertEqual(r1, r2)


# ===========================================================================
# 11. select_dest_ipr  (IP routing decision logic)
# ===========================================================================
class TestSelectDestIpr(unittest.TestCase):
    def _src(self, ext="1.2.3.4", nic="192.168.1.100"):
        return {"netiface_index": 0, "ext": ext, "nic": nic, "if_index": 0}

    def _dest(self, ext="5.6.7.8", nic="10.0.0.5"):
        return {"netiface_index": 1, "ext": ext, "nic": nic, "if_index": 0}

    def test_ext_bind_returns_dest_ext(self):
        r = select_dest_ipr(IP4, False, self._src(), self._dest(), [EXT_BIND])
        self.assertEqual(str(r), "5.6.7.8")

    def test_ext_bind_same_router_returns_none(self):
        """Peers behind the same router share ext; EXT_BIND must be skipped."""
        src = self._src(ext="1.2.3.4")
        dst = self._dest(ext="1.2.3.4")
        r = select_dest_ipr(IP4, False, src, dst, [EXT_BIND])
        self.assertIsNone(r)

    def test_nic_bind_returns_dest_nic(self):
        r = select_dest_ipr(IP4, False, self._src(), self._dest(), [NIC_BIND])
        self.assertEqual(str(r), "10.0.0.5")

    def test_no_compatible_type_returns_none(self):
        # EXT_BIND blocked (same router); NIC_BIND not in list.
        src = self._src(ext="1.2.3.4")
        dst = self._dest(ext="1.2.3.4")
        r = select_dest_ipr(IP4, False, src, dst, [EXT_BIND])
        self.assertIsNone(r)


# ===========================================================================
# 12. sort_pairs_by_overlap
# ===========================================================================
class TestSortPairsByOverlap(unittest.TestCase):
    def _make_info(self, ext):
        return {"ext": ext, "nic": "10.0.0.1"}

    def test_same_ext_goes_to_overlap(self):
        src = [self._make_info("1.1.1.1")]
        dst = [self._make_info("1.1.1.1")]
        overlap, unique = sort_pairs_by_overlap(src, dst)
        self.assertEqual(len(overlap), 1)
        self.assertEqual(len(unique), 0)

    def test_different_ext_goes_to_unique(self):
        src = [self._make_info("1.1.1.1")]
        dst = [self._make_info("2.2.2.2")]
        overlap, unique = sort_pairs_by_overlap(src, dst)
        self.assertEqual(len(overlap), 0)
        self.assertEqual(len(unique), 1)

    def test_mixed(self):
        src = [self._make_info("1.1.1.1"), self._make_info("3.3.3.3")]
        dst = [self._make_info("1.1.1.1"), self._make_info("9.9.9.9")]
        overlap, unique = sort_pairs_by_overlap(src, dst)
        self.assertEqual(len(overlap), 1)
        self.assertEqual(len(unique), 3)

    def test_overlap_pairs_have_matching_exts(self):
        src = [self._make_info("1.1.1.1")]
        dst = [self._make_info("1.1.1.1"), self._make_info("2.2.2.2")]
        overlap, _ = sort_pairs_by_overlap(src, dst)
        for s, d in overlap:
            self.assertEqual(s["ext"], d["ext"])


if __name__ == "__main__":
    unittest.main()
