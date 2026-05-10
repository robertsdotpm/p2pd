"""Real-world Gate connector for the gate_sweep matrix runner.

Spins up a default Gate (no --nic, --ip, or --port pinning), calls
``gate.connect(peer.find(target), test_all_phases=True)`` so every
auto_connect phase runs serially regardless of which one wins first,
sends a PING and reads back the PONG.

Per-phase outcomes are picked up from the [AC-PHASE] log lines auto_connect
prints to stdout in test_all_phases mode. We additionally print:

    OUTCOME winner_plugin=<name|none>
    OUTCOME echo_ok=<true|false>
    OUTCOME echo_msg=<bytes-repr>

so the orchestrator can grep a single stable shape per iteration.
"""
import asyncio
import os
import sys

from aionetiface import aionetiface_setup_event_loop, IP4, IP6
aionetiface_setup_event_loop()

sys.argv = [sys.argv[0]]

from p2pd.gate import Gate, peer


def parse_afs(env_value):
    """Parse WG_AFS env: '4' / '6' / '4,6' / unset -> None (both)."""
    if not env_value:
        return None
    out = []
    for tok in env_value.replace(" ", "").split(","):
        if tok == "4":
            out.append(IP4)
        elif tok == "6":
            out.append(IP6)
    return tuple(out) if out else None


async def main():
    target = os.environ["WG_TARGET"]
    name = os.environ.get("WG_CONNECT_NAME") or None
    # Default 900s: test_all_phases runs every phase serially -- tcp_punch
    # plugin timeout is 180s, udp/spray 150s, turn 60s. With the phase loop
    # iterating route_types and AFs per phase, the worst-case serial budget
    # is multiples of those. 300s used to fire mid-cascade, dropping a
    # winner pipe phase1 had already produced. 900s is generous but covers
    # every realistic cumulative path.
    timeout = float(os.environ.get("WG_TIMEOUT", "900"))

    afs = parse_afs(os.environ.get("WG_AFS"))
    async with (Gate(name=name) if name else Gate()) as gate:
        print("WG_CONNECTOR_READY: {0} afs={1}".format(
            gate.full_name or "?", afs,
        ), flush=True)
        link = await gate.connect(
            peer.find(target),
            test_all_phases=True,
            timeout=timeout,
            afs=afs,
        )
        if link is None:
            print("OUTCOME winner_plugin=none", flush=True)
            print("OUTCOME echo_ok=false", flush=True)
            return
        winner = type(link.pipe).__name__
        # The plugin name is informational here -- auto_connect's
        # [AC-PHASE] lines already disclose which plugin won. We
        # echo the underlying pipe class instead so the orchestrator
        # can sanity-check transport.
        print("OUTCOME winner_pipe={0}".format(winner), flush=True)
        ok = False
        msg = None
        try:
            async with link:
                await link.send(b"PING:gate_sweep")

                async def one():
                    async for m in link:
                        return m

                msg = await asyncio.wait_for(one(), timeout=10.0)
                ok = msg is not None and msg.startswith(b"PONG:")
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pylint: disable=broad-except
            print("OUTCOME echo_exc={0}".format(repr(exc)), flush=True)
        print("OUTCOME echo_ok={0}".format("true" if ok else "false"), flush=True)
        if msg is not None:
            print("OUTCOME echo_msg={0!r}".format(msg[:80]), flush=True)


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
