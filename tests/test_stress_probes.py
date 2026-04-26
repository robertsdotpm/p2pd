"""
Cross-platform flakiness probes.

Each probe targets a subsystem we've seen flake somewhere in the
matrix (interface load, STUN, nickname, Node start, concurrent Node
init, socket allocator under hammer, reverse_connect on the local
host). Failures emit a UserWarning and the test PASSES -- this file
is a flake-rate signal, not a gate. The matrix runner picks the
warnings up via stderr; the gate stays unpinned.

Why pass-on-failure: these probes intentionally exercise paths that
flake on environmental conditions (network reachability, kernel
quirks per platform). Hard-failing would cause a healthy build to
gate-halt every time the home ISP blips. Surfacing flakes as
warnings keeps that signal visible without making the matrix
pretend it's a regression.

Tunables (env vars):
    STRESS_PROBE_CYCLES        cycles per parameterised step (default 5)
    STRESS_PROBE_CONCURRENCY   parallel Node count for the concurrent
                               step (default 4)
    STRESS_PROBE_HAMMER        TCP-listen/connect cycles for the
                               socket-hammer step (default 50)
    STRESS_PROBE_HEAVY         "0" to skip reverse_connect (default 1)
"""

import asyncio
import os
import socket as stdsocket
import time
import unittest
import warnings

from aionetiface.testing import AsyncTestCase


CYCLES = int(os.environ.get("STRESS_PROBE_CYCLES", "5"))
CONCURRENCY = int(os.environ.get("STRESS_PROBE_CONCURRENCY", "4"))
HAMMER_CYCLES = int(os.environ.get("STRESS_PROBE_HAMMER", "50"))
INCLUDE_HEAVY = os.environ.get("STRESS_PROBE_HEAVY", "1") != "0"


def warn_on_failure(label, fn):
    """Return an async wrapper that runs fn(), warns + swallows on exception.

    Used by each test method below so the test ALWAYS passes -- a
    healthy run produces no warnings, a flake produces a clear
    UserWarning identifying which probe + which exception.
    """
    async def wrapper(*args, **kwargs):
        try:
            result = await fn(*args, **kwargs)
            return ("ok", result)
        except Exception as exc:
            warnings.warn(
                "{0} probe flaked: {1}: {2}".format(
                    label, type(exc).__name__, exc,
                ),
                UserWarning,
            )
            return ("flake", exc)
    return wrapper


# ---------------------------------------------------------------------------
# Probe primitives. Each returns a small dict of observations or raises;
# warn_on_failure converts raises into warnings.
# ---------------------------------------------------------------------------


async def probe_interface_load():
    """Single Interface() + nat type read."""
    from aionetiface import Interface
    nic = await Interface()
    return {
        "name": getattr(nic, "name", "?"),
        "supported": list(nic.supported()),
        "nat_type": (nic.nat or {}).get("type"),
    }


async def probe_stun_load():
    """TCP STUN clients on the default NIC across each AF."""
    from aionetiface import Interface
    from p2pd.node.node_utils import load_stun_clients
    nic = await Interface()
    stun_clients = await load_stun_clients([nic])
    out = {}
    for af, by_index in stun_clients.items():
        total = 0
        if isinstance(by_index, dict):
            for clients in by_index.values():
                try:
                    total += len(clients)
                except TypeError:
                    pass
        out[str(af)] = total
    return out


async def probe_nickname_round_trip():
    """PNP put + get + delete round-trip on a fresh ephemeral name.

    The earlier XP failure here was a cascade from broken interface
    load -- get returned FullNameFailure because Nickname session
    state never finished initialising. Captured here so a future
    PNP regression flares as a warning before it tanks the matrix.
    """
    from aionetiface import Interface, SysClock
    from p2pd.node.nickname import Nickname

    nic = await Interface()
    sk_bytes = os.urandom(32)
    from ecdsa import SigningKey, SECP256k1
    sk = SigningKey.from_string(sk_bytes, curve=SECP256k1)
    sys_clock = SysClock(nic, ntp=time.time())
    nick = await Nickname(sk, [nic], sys_clock)

    name = "stressprobe" + str(int(time.time() * 1000))[-8:]
    val = b"stress-probe-value"
    fqn = await asyncio.wait_for(nick.put(name, val), timeout=30)
    got = await asyncio.wait_for(nick.get(fqn), timeout=30)
    try:
        await asyncio.wait_for(nick.delete(fqn), timeout=30)
    except Exception:
        pass
    if got is None:
        raise AssertionError("PNP get returned None for {0!r}".format(fqn))
    return {"fqn": fqn, "got_ok": True}


async def probe_node_start():
    """Full Node().start() + close + addr_bytes check.

    Uses a fresh listen port per call so back-to-back invocations
    don't collide on TIME_WAIT. NODE_TEST_CONF disables UPnP /
    nickname / STUN clients so the probe measures the core startup
    path, not optional network reachability.
    """
    from p2pd.node.node import Node, NODE_PORT
    from p2pd.node.node_defs import NODE_TEST_CONF
    port = NODE_PORT + 6000 + (int(time.time() * 1000) % 5000)
    node = await asyncio.wait_for(
        Node(port=port, conf=NODE_TEST_CONF).start(), timeout=30,
    )
    try:
        addr = node.addr_bytes
        return {"addr_len": len(addr) if addr else 0, "port": port}
    finally:
        try:
            await asyncio.wait_for(node.close(), timeout=15)
        except Exception:
            pass


async def probe_concurrent_node_init():
    """Spin up CONCURRENCY Nodes in parallel; await all start; close all.

    Catches races in init paths shared across Nodes -- WMIC lock
    contention on Windows, MQTT broker rate-limiting, NTP fan-out
    collisions on overlapping requests.
    """
    from p2pd.node.node import Node, NODE_PORT
    from p2pd.node.node_defs import NODE_TEST_CONF
    base = NODE_PORT + 7000 + (int(time.time() * 1000) % 4000)
    nodes = [Node(port=base + i, conf=NODE_TEST_CONF) for i in range(CONCURRENCY)]

    started = []
    try:
        results = await asyncio.gather(
            *(asyncio.wait_for(n.start(), timeout=45) for n in nodes),
            return_exceptions=True,
        )
        ok_count = 0
        fails = []
        for n, r in zip(nodes, results):
            if isinstance(r, BaseException):
                fails.append("port={0} {1}".format(
                    n.listen_port, type(r).__name__,
                ))
                continue
            ok_count += 1
            started.append(n)
        if fails:
            raise AssertionError(
                "{0}/{1} concurrent Node starts failed: {2}".format(
                    len(fails), CONCURRENCY, fails,
                )
            )
        return {"concurrency": CONCURRENCY, "started": ok_count}
    finally:
        for n in started:
            try:
                await asyncio.wait_for(n.close(), timeout=8)
            except Exception:
                pass


async def probe_socket_hammer():
    """Rapid TCP listen + connect + accept + close cycles on 127.0.0.1.

    Stresses the kernel socket allocator + TIME_WAIT handling.
    A regression in SO_REUSEADDR or aionetiface's
    avoid_time_wait/SO_LINGER handling shows up as EADDRINUSE
    after a few dozen cycles.
    """
    bound = 0
    for _ in range(HAMMER_CYCLES):
        srv = stdsocket.socket(stdsocket.AF_INET, stdsocket.SOCK_STREAM)
        srv.setsockopt(stdsocket.SOL_SOCKET, stdsocket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        cli = stdsocket.socket(stdsocket.AF_INET, stdsocket.SOCK_STREAM)
        cli.settimeout(2.0)
        cli.connect(("127.0.0.1", port))
        accepted, _ = srv.accept()
        accepted.close()
        cli.close()
        srv.close()
        bound += 1
    return {"cycles": bound}


async def probe_reverse_connect_local():
    """Two-Node auto_connect with direct_connect stripped from the initiator.

    Compresses test_auto_connect_reverse to a self-contained probe
    so the matrix gets a quick reverse-connect signal even when the
    full integration test isn't in the gate.  Returns the winning
    plugin name -- 'ReverseConnectPlugin' on a healthy host, anything
    else (TURNPlugin most often) means the local routing path
    direct_connect would normally win on isn't reachable.
    """
    from aionetiface import IP4, list_interfaces, load_interfaces, Interface
    from p2pd.node.node import Node, NODE_PORT
    from p2pd.node.node_defs import NODE_TEST_CONF
    from p2pd.node.auto_connect import auto_connect

    if_names = await list_interfaces()
    if not if_names:
        raise AssertionError("no interfaces visible")

    nics = await load_interfaces(if_names[:2], Interface)
    base = NODE_PORT + 8000 + (int(time.time() * 1000) % 1000)
    a = Node(ifs=nics, port=base, conf=NODE_TEST_CONF)
    b = Node(ifs=nics, port=base + 1, conf=NODE_TEST_CONF)

    try:
        await asyncio.wait_for(a.start(), timeout=30)
        await asyncio.wait_for(b.start(), timeout=30)
        a.traversal.plugin_loaders.pop("direct_connect", None)
        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(a, b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            raise AssertionError("auto_connect timed out")
        plugin_name = type(plugin).__name__ if plugin is not None else None
        try:
            if pipe is not None:
                await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass
        if plugin_name != "ReverseConnectPlugin":
            raise AssertionError(
                "reverse_connect lost the race -- got {0!r}".format(plugin_name)
            )
        return {"plugin": plugin_name}
    finally:
        for n in (b, a):
            try:
                await asyncio.wait_for(n.close(), timeout=10)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Test class. Each probe gets its own test method so the matrix
# runner reports per-probe pass/skip/warn results. The methods
# always pass -- failures become UserWarnings via warn_on_failure.
# ---------------------------------------------------------------------------


class TestStressProbes(AsyncTestCase):
    """Soft probes that warn-on-flake instead of failing the matrix."""

    async def asyncSetUp(self):
        # Each probe is independent; setup is intentionally empty.
        pass

    async def test_interface_load(self):
        wrapper = warn_on_failure("interface_load", probe_interface_load)
        for _ in range(CYCLES):
            await wrapper()

    async def test_stun_load(self):
        wrapper = warn_on_failure("stun_load", probe_stun_load)
        for _ in range(CYCLES):
            await wrapper()

    async def test_nickname_round_trip(self):
        wrapper = warn_on_failure("nickname_round_trip", probe_nickname_round_trip)
        for _ in range(CYCLES):
            await wrapper()

    async def test_node_start(self):
        wrapper = warn_on_failure("node_start", probe_node_start)
        for _ in range(CYCLES):
            await wrapper()

    async def test_concurrent_node_init(self):
        wrapper = warn_on_failure("concurrent_node_init", probe_concurrent_node_init)
        # A single concurrent batch is enough -- repeating just stacks
        # MQTT broker rate-limits without adding signal.
        await wrapper()

    async def test_socket_hammer(self):
        wrapper = warn_on_failure("socket_hammer", probe_socket_hammer)
        await wrapper()

    async def test_reverse_connect_local(self):
        if not INCLUDE_HEAVY:
            self.skipTest("STRESS_PROBE_HEAVY=0; reverse_connect probe disabled")
        wrapper = warn_on_failure("reverse_connect_local", probe_reverse_connect_local)
        await wrapper()


if __name__ == "__main__":
    unittest.main()
