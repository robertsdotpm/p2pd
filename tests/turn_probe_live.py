"""
Standalone TURN relay probe.

For each public TURN server in servers.json, spin up two TURNClient
instances pointing at THAT same server, cross-register them as
peers, send a small payload from A -> B, and check whether B's
msg_cb received it within 5 seconds. Prints a compact per-server
verdict.

The point: isolate whether live-TURN flakiness is a server-quality
issue (server X always drops, server Y works) vs a local
environment / OS-stack issue (every server fails on Vista, all
work on Win10).

Not a unittest -- intended to be run manually:

    python tests/turn_probe_live.py [--af 4|6] [--limit N]

The script does NOT depend on Node / auto_connect / signaling /
MQTT. It uses only the TURNClient + a NIC. That makes it easier to
attribute failures to layers below auto_connect when they happen.
"""
import argparse
import asyncio
import sys
import time
import traceback

from aionetiface import (
    IP4, IP6, UDP, Interface, get_infra, list_interfaces, load_interfaces,
)
from warpgate.traversal.plugins.turn.turn_client import TURNClient


PROBE_PAYLOAD = b"TURN-PROBE-PAYLOAD-12345"


async def run_one_server(af, server, nic, idx, total):
    """Test a single TURN server end-to-end. Returns a compact dict result."""
    name = "{0}:{1}".format(server.get("ip"), server.get("port"))
    fqns = server.get("fqns") or []
    label = "{0}/{1}  {2}  {3}".format(idx + 1, total, name, ",".join(fqns) or "-")

    started = time.time()
    received = []
    received_event = asyncio.Event()

    def on_msg(msg, client_tup, pipe):
        # Sync callback registered via add_msg_cb on the client B side.
        # Append every chunk; release the awaiter when the payload arrives.
        received.append(msg)
        if msg and PROBE_PAYLOAD in msg:
            received_event.set()

    a = b = None
    try:
        a = TURNClient(
            af=af,
            dest=(server["ip"], server["port"]),
            nic=nic,
            auth=(server.get("user", ""), server.get("password", "")),
            realm=None,
        )
        b = TURNClient(
            af=af,
            dest=(server["ip"], server["port"]),
            nic=nic,
            auth=(server.get("user", ""), server.get("password", "")),
            realm=None,
            msg_cb=on_msg,
        )

        try:
            await asyncio.wait_for(asyncio.gather(a.start(), b.start()), timeout=15)
        except asyncio.TimeoutError:
            return {
                "label": label,
                "phase": "allocate",
                "ok": False,
                "detail": "allocate/auth timed out >15s",
                "elapsed": time.time() - started,
            }

        a_peer, a_relay = await a.client_tup_future, await a.relay_tup_future
        b_peer, b_relay = await b.client_tup_future, await b.relay_tup_future

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    a.accept_peer(b_peer, b_relay),
                    b.accept_peer(a_peer, a_relay),
                ),
                timeout=10,
            )
        except asyncio.TimeoutError:
            return {
                "label": label,
                "phase": "create-permission",
                "ok": False,
                "detail": "CreatePermission round-trip timed out",
                "elapsed": time.time() - started,
            }

        try:
            await a.send(PROBE_PAYLOAD, dest_tup=b_peer)
        except Exception as exc:
            return {
                "label": label,
                "phase": "send",
                "ok": False,
                "detail": "send raised: {0!r}".format(exc),
                "elapsed": time.time() - started,
            }

        try:
            await asyncio.wait_for(received_event.wait(), timeout=5)
        except asyncio.TimeoutError:
            return {
                "label": label,
                "phase": "relay-recv",
                "ok": False,
                "detail": "B did not see payload in 5s; got {0} chunks".format(len(received)),
                "elapsed": time.time() - started,
            }

        return {
            "label": label,
            "phase": "ok",
            "ok": True,
            "detail": "round-trip in {0:.2f}s".format(time.time() - started),
            "elapsed": time.time() - started,
        }
    except Exception:
        return {
            "label": label,
            "phase": "exception",
            "ok": False,
            "detail": traceback.format_exc().strip().splitlines()[-1],
            "elapsed": time.time() - started,
        }
    finally:
        for c in (a, b):
            if c is not None:
                try:
                    await asyncio.wait_for(c.close(), timeout=5)
                except Exception:
                    pass


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--af", type=int, default=4, choices=[4, 6],
                        help="address family: 4 or 6 (default 4)")
    parser.add_argument("--limit", type=int, default=0,
                        help="stop after N servers (0 = all)")
    args = parser.parse_args()

    af = IP4 if args.af == 4 else IP6

    print("[TURN-PROBE] loading first NIC...")
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names, Interface, skip_nat=True)
    if not ifs:
        print("[TURN-PROBE] no NICs -- abort")
        return 2
    nic = ifs[0]
    print("[TURN-PROBE] using NIC {0!r}, af={1}".format(getattr(nic, "id", "?"), af))

    groups = get_infra(af, UDP, "TURN", no=200)
    flat = []
    for g in groups:
        if g:
            flat.append(g[0])
    if args.limit:
        flat = flat[: args.limit]
    print("[TURN-PROBE] {0} TURN servers to probe".format(len(flat)))

    results = []
    for idx, server in enumerate(flat):
        r = await run_one_server(af, server, nic, idx, len(flat))
        verdict = "PASS" if r["ok"] else "FAIL"
        print("[TURN-PROBE] {0:4} {1}  phase={2}  {3}  ({4:.1f}s)".format(
            verdict, r["label"], r["phase"], r["detail"], r["elapsed"],
        ))
        results.append(r)

    pass_n = sum(1 for r in results if r["ok"])
    fail_n = len(results) - pass_n
    print("[TURN-PROBE] summary: pass={0} fail={1}/{2}".format(pass_n, fail_n, len(results)))
    by_phase = {}
    for r in results:
        if not r["ok"]:
            by_phase[r["phase"]] = by_phase.get(r["phase"], 0) + 1
    if by_phase:
        print("[TURN-PROBE] failure phases: {0}".format(by_phase))

    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    rc = asyncio.get_event_loop().run_until_complete(main())
    sys.exit(rc)
