"""
XP-targeted flakiness probe.

Loops the four subsystems we've seen flake on XP:
  1. Interface() load
  2. STUN client load on that interface
  3. Nickname.put/get/delete (PNP TCP+TLS)
  4. Node().start() + close()

For each iteration we record pass/fail + the exception type + a one-line
summary so a 20x run yields a per-subsystem flake rate. The point is to
isolate which layer's the actual flake (network ENV vs code bug) without
having to roll out per-subsystem instrumentation across the whole matrix.

Upload + run on XP only:

    scp scripts/xp_stress.py matthew@10.0.1.132:C:/xp_stress.py
    ssh matthew@10.0.1.132 'C:/py3/python.exe C:/xp_stress.py'
"""

import asyncio
import os
import sys
import time
import traceback


ITERATIONS = int(os.environ.get("XP_STRESS_ITERATIONS", "10"))


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
    }
    failures = []

    for i in range(ITERATIONS):
        banner("iteration {0}/{1}".format(i + 1, ITERATIONS))
        for label, factory in (
            ("interface", step_interface),
            ("stun", step_stun),
            ("nickname", step_nickname),
            ("node", step_node),
        ):
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
