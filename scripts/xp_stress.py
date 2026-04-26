"""
XP-targeted flakiness probe.

Loops the subsystems we've seen flake on XP:
  1. Interface() load
  2. STUN client load on that interface
  3. Nickname.put/get/delete (PNP TCP+TLS)
  4. Node().start() + close()  (with phase tracer)
  5. CONCURRENT: spin up N Nodes simultaneously (catches race
     conditions in shared resource init -- WMIC lock contention,
     MQTT broker rate limiting, NTP fan-out)
  6. SOCKET hammer: rapid TCP listen + connect + close cycles to
     catch TIME_WAIT / SO_REUSEADDR regressions
  7. REVERSE_CONNECT in-process: two Nodes + auto_connect on the
     same XP host (the matrix's heaviest test_auto_connect_reverse
     compressed to a self-contained probe)

For each iteration we record pass/fail + the exception type + a one-line
summary so a 20x run yields a per-subsystem flake rate. The point is to
isolate which layer's the actual flake (network ENV vs code bug) without
having to roll out per-subsystem instrumentation across the whole matrix.

Upload + run on XP only:

    scp scripts/xp_stress.py matthew@10.0.1.132:C:/xp_stress.py
    ssh matthew@10.0.1.132 'C:/py3/python.exe C:/xp_stress.py'

Tunables (env vars):
    XP_STRESS_ITERATIONS  outer loop count (default 5)
    XP_STRESS_CONCURRENCY parallel Node count for step_concurrent (4)
    XP_STRESS_HAMMER      socket hammer cycles per iteration (50)
    XP_STRESS_HEAVY       1 = include reverse_connect step (default 1)
"""

import asyncio
import os
import sys
import time
import traceback


ITERATIONS = int(os.environ.get("XP_STRESS_ITERATIONS", "5"))
CONCURRENCY = int(os.environ.get("XP_STRESS_CONCURRENCY", "4"))
HAMMER_CYCLES = int(os.environ.get("XP_STRESS_HAMMER", "50"))
INCLUDE_HEAVY = os.environ.get("XP_STRESS_HEAVY", "1") != "0"


def banner(title):
    print("")
    print("=" * 72)
    print(title)
    print("=" * 72)


def fmt_exc(exc):
    return "{0}: {1}".format(type(exc).__name__, exc)


async def step_interface():
    from aionetiface import Interface
    nic = await Interface()
    info = {
        "name": getattr(nic, "name", "?"),
        "supported": list(nic.supported()),
        "nat_type": (nic.nat or {}).get("type"),
    }
    return info


async def step_stun():
    """Load TCP STUN clients across each AF on the default NIC.

    Mirrors what node_start.load_p2p_stun_clients does, isolated so we
    can see if TCP STUN to the public pool is the flaky bit.
    """
    from aionetiface import Interface
    from p2pd.node.node_utils import load_stun_clients
    nic = await Interface()
    stun_clients = await load_stun_clients([nic])
    # load_stun_clients returns {af: {if_index: [client, ...]}}.
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


async def step_nickname():
    """Full PNP put/get/delete round-trip on a fresh ephemeral name.

    Uses the same code path test_network exercises but standalone so a
    PNP TCP timeout shows up as one isolated failure rather than
    cascading into a full Node start.
    """
    from aionetiface import Interface, SysClock
    from p2pd.node.nickname import Nickname

    nic = await Interface()
    # XP doesn't have `secrets` (3.6+); pull random bytes via os.urandom.
    sk_bytes = os.urandom(32)
    from ecdsa import SigningKey, SECP256k1
    sk = SigningKey.from_string(sk_bytes, curve=SECP256k1)
    sys_clock = SysClock(nic, ntp=time.time())
    nick = await Nickname(sk, [nic], sys_clock)

    name = "xpstress" + str(int(time.time() * 1000))[-8:]
    val = b"xp-stress-value"
    fqn = await asyncio.wait_for(nick.put(name, val), timeout=30)
    print("    [nickname-dbg] put OK fqn={0!r}".format(fqn))

    # Catch the read-after-write window: try the immediate get,
    # and if it fails, retry after a 2s settle and report both.
    immediate_err = None
    try:
        got = await asyncio.wait_for(nick.get(fqn), timeout=30)
        print("    [nickname-dbg] immediate get returned {0!r}".format(
            got is not None
        ))
    except Exception as exc:
        immediate_err = exc
        got = None
        print("    [nickname-dbg] immediate get failed: {0!r}".format(exc))

    settled = None
    settled_err = None
    if got is None:
        await asyncio.sleep(2)
        try:
            settled = await asyncio.wait_for(nick.get(fqn), timeout=30)
            print("    [nickname-dbg] after 2s settle, get returned {0!r}".format(
                settled is not None
            ))
        except Exception as exc:
            settled_err = exc
            print("    [nickname-dbg] after settle, get still failed: {0!r}".format(
                exc
            ))

    try:
        await asyncio.wait_for(nick.delete(fqn), timeout=30)
    except Exception as exc:
        print("    [nickname-dbg] delete failed: {0!r}".format(exc))

    return {
        "fqn": fqn,
        "immediate_got": got is not None,
        "settled_got": settled is not None,
        "immediate_err": repr(immediate_err) if immediate_err else None,
        "settled_err": repr(settled_err) if settled_err else None,
    }


async def step_node():
    """Full node start + addr_bytes + close. Surfaces the
    'A Future or coroutine is required' error we saw on XP.

    Uses a fresh listen port per call so back-to-back runs in the
    same loop don't collide on TIME_WAIT.
    """
    from p2pd.node.node import Node, NODE_PORT
    from p2pd.node import node_start as ns_module
    port = NODE_PORT + 6000 + (int(time.time() * 1000) % 5000)

    # Wrap each named startup phase to record entry/exit times so we
    # can see which phase eats the budget on XP. Restore originals
    # afterwards so the next iteration measures fresh.
    phase_timings = []
    phase_names = [
        "load_network_interfaces",
        "load_machine_identity",
        "initialize_system_clock",
        "load_p2p_stun_clients",
        "setup_router_and_signal",
        "initialize_punch_coordination",
        "build_node_address",
        "setup_nickname_service",
        "setup_traversal_plugins",
        "finalize_port_forwarding",
    ]
    originals = {}
    for name in phase_names:
        if not hasattr(ns_module, name):
            continue
        fn = getattr(ns_module, name)
        # Only wrap async coroutine functions; wrapping a plain sync
        # function would change its return type from value to coroutine
        # and break callers (build_node_address used to warn about
        # exactly this).
        if not asyncio.iscoroutinefunction(fn):
            continue
        originals[name] = fn

        def builder(n=name, fn=fn):
            async def wrapper(*args, **kwargs):
                t0 = time.time()
                try:
                    return await fn(*args, **kwargs)
                finally:
                    elapsed = time.time() - t0
                    phase_timings.append((n, elapsed))
                    print("        [node-phase] {0:35s} {1:6.2f}s".format(n, elapsed))
            return wrapper
        setattr(ns_module, name, builder())

    try:
        # Explicit .start() returns a coroutine -- Node() alone is
        # awaitable via __await__ but Python 3.5.0's
        # asyncio.ensure_future only accepts coroutines/futures.
        node = await asyncio.wait_for(Node(port=port).start(), timeout=30)
        try:
            addr = node.addr_bytes
            return {"addr_len": len(addr) if addr else 0,
                    "phases": phase_timings}
        finally:
            try:
                await asyncio.wait_for(node.close(), timeout=15)
            except Exception:
                pass
    finally:
        for name, fn in originals.items():
            setattr(ns_module, name, fn)


async def step_concurrent():
    """Spin up CONCURRENCY Nodes in parallel, await all start, close all.

    Catches races in init paths shared across Nodes -- WMIC lock
    contention (now mitigated by iphlpapi-as-primary), MQTT broker
    rate-limits, NTP fan-out collisions. Each Node uses a port
    derived from time + offset so concurrent runs don't collide.
    """
    from p2pd.node.node import Node, NODE_PORT
    base = NODE_PORT + 7000 + (int(time.time() * 1000) % 4000)
    nodes = [Node(port=base + i) for i in range(CONCURRENCY)]
    started_at = time.time()

    async def run_one(node):
        return await asyncio.wait_for(node.start(), timeout=45)

    started = []
    try:
        results = await asyncio.gather(
            *(run_one(n) for n in nodes), return_exceptions=True
        )
        ok_count = 0
        fails = []
        for n, r in zip(nodes, results):
            if isinstance(r, BaseException):
                fails.append("{0}: {1}".format(n.listen_port, fmt_exc(r)))
                continue
            ok_count += 1
            started.append(n)
        elapsed = time.time() - started_at
        return {
            "concurrency": CONCURRENCY,
            "started": ok_count,
            "elapsed_s": round(elapsed, 2),
            "fails": fails,
        }
    finally:
        # Best-effort close every node we managed to start.
        for n in started:
            try:
                await asyncio.wait_for(n.close(), timeout=8)
            except Exception:
                pass


async def step_socket_hammer():
    """Rapid TCP listen + connect + close cycles on 127.0.0.1.

    Stresses XP's socket allocator + TIME_WAIT handling. A regression
    in SO_REUSEADDR or aionetiface's avoid_time_wait/SO_LINGER setup
    surfaces as 'Address already in use' after a few dozen cycles.
    """
    import socket as stdsocket
    bound_count = 0
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
        bound_count += 1
    return {"cycles": bound_count}


async def step_reverse_connect():
    """Two-Node reverse_connect echo round-trip on the local host.

    Compresses test_auto_connect_reverse to a self-contained probe so
    we can check pipe rendezvous works on XP without firing the whole
    matrix. Returns the winning plugin name -- expect 'ReverseConnectPlugin'
    on a healthy box.
    """
    from aionetiface import IP4
    from aionetiface import (
        list_interfaces, load_interfaces, Interface,
    )
    from p2pd.node.node import Node, NODE_PORT
    from p2pd.node.auto_connect import auto_connect

    if_names = await list_interfaces()
    if len(if_names) < 1:
        return {"skipped": "no interfaces"}

    nics = await load_interfaces(if_names[:2], Interface)
    base = NODE_PORT + 8000 + (int(time.time() * 1000) % 1000)
    a = Node(ifs=nics, port=base)
    b = Node(ifs=nics, port=base + 1)

    try:
        await asyncio.wait_for(a.start(), timeout=30)
        await asyncio.wait_for(b.start(), timeout=30)
        # Force reverse path: drop direct_connect from initiator only.
        a.traversal.plugin_loaders.pop("direct_connect", None)
        try:
            pipe, plugin = await asyncio.wait_for(
                auto_connect(a, b.addr_bytes, timeout=20),
                timeout=25,
            )
        except asyncio.TimeoutError:
            return {"converged": False, "reason": "auto_connect timeout"}
        plugin_name = type(plugin).__name__ if plugin is not None else None
        try:
            if pipe is not None:
                await asyncio.wait_for(pipe.close(), timeout=5)
        except Exception:
            pass
        return {"converged": pipe is not None, "plugin": plugin_name}
    finally:
        for n in (b, a):
            try:
                await asyncio.wait_for(n.close(), timeout=10)
            except Exception:
                pass


async def run_step(label, coro_factory):
    """Run a single step, print a one-line PASS/FAIL summary,
    return (ok, exc) so the caller can tally flake rates."""
    started = time.time()
    try:
        result = await coro_factory()
        elapsed = time.time() - started
        print("    PASS  {0:6.2f}s  {1}  -> {2!r}".format(elapsed, label, result))
        return (True, None)
    except Exception as exc:
        elapsed = time.time() - started
        print("    FAIL  {0:6.2f}s  {1}  -> {2}".format(elapsed, label, fmt_exc(exc)))
        traceback.print_exc()
        return (False, exc)


async def main():
    banner("xp_stress: {0} iterations".format(ITERATIONS))
    print("python: {0}".format(sys.version.replace("\n", " ")))
    print("platform: {0}".format(sys.platform))
    print("cwd: {0}".format(os.getcwd()))
    print("")

    tally = {
        "interface": [0, 0],
        "stun": [0, 0],
        "nickname": [0, 0],
        "node": [0, 0],
        "concurrent": [0, 0],
        "socket_hammer": [0, 0],
    }
    if INCLUDE_HEAVY:
        tally["reverse_connect"] = [0, 0]
    failures = []

    steps = [
        ("interface", step_interface),
        ("stun", step_stun),
        ("nickname", step_nickname),
        ("node", step_node),
        ("concurrent", step_concurrent),
        ("socket_hammer", step_socket_hammer),
    ]
    if INCLUDE_HEAVY:
        steps.append(("reverse_connect", step_reverse_connect))

    for i in range(ITERATIONS):
        banner("iteration {0}/{1}".format(i + 1, ITERATIONS))
        for label, factory in steps:
            ok, exc = await run_step(label, factory)
            tally[label][0 if ok else 1] += 1
            if not ok:
                failures.append((i + 1, label, fmt_exc(exc)))

    banner("summary")
    for label, (ok, fail) in tally.items():
        total = ok + fail
        rate = 100.0 * fail / total if total else 0.0
        print("  {0:10s}  pass={1}  fail={2}  flake={3:.0f}%".format(label, ok, fail, rate))

    if failures:
        banner("failures")
        for i, label, msg in failures:
            print("  iter={0:2d}  step={1:10s}  {2}".format(i, label, msg))
    else:
        print("\n  all green")


if __name__ == "__main__":
    try:
        from aionetiface.testing import aionetiface_setup_event_loop
        aionetiface_setup_event_loop()
    except Exception as exc:
        print("setup_event_loop failed: {0}".format(exc))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
