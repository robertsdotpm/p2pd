"""Like gate_connect but pins a specific plugin via WG_PLUGIN env.

Used by gate_sweep for per-plugin diagnostic runs (e.g. forcing TURN
on its own to debug why phase4 produces no pipe in mixed runs).

WG_TARGET   -- nickname to dial
WG_PLUGIN   -- single plugin name (turn / tcp_punch / etc)
WG_TIMEOUT  -- seconds (default 120)
"""
import asyncio
import os
import sys

from aionetiface import aionetiface_setup_event_loop
aionetiface_setup_event_loop()

sys.argv = [sys.argv[0]]

from p2pd.gate import Gate, peer


async def main():
    target = os.environ["WG_TARGET"]
    plugin_name = os.environ["WG_PLUGIN"]
    timeout = float(os.environ.get("WG_TIMEOUT", "120"))

    async with Gate() as gate:
        print("WG_CONNECTOR_READY: {0}".format(gate.full_name or "?"), flush=True)
        try:
            link = await gate.connect(
                peer.find(target),
                plugins=[plugin_name],
                timeout=timeout,
            )
        except Exception as exc:
            print("OUTCOME connect_exc={0}".format(repr(exc)), flush=True)
            return
        if link is None:
            print("OUTCOME no_pipe", flush=True)
            return
        print("OUTCOME winner_pipe={0}".format(type(link.pipe).__name__), flush=True)
        ok = False
        try:
            async with link:
                await link.send(b"PING:" + plugin_name.encode())

                async def one():
                    async for m in link:
                        return m

                msg = await asyncio.wait_for(one(), timeout=10.0)
                ok = msg is not None and msg.startswith(b"PONG:")
                print("OUTCOME echo_ok={0} msg={1!r}".format(
                    "true" if ok else "false", msg,
                ), flush=True)
        except asyncio.TimeoutError:
            print("OUTCOME echo_timeout", flush=True)
        except Exception as exc:  # pylint: disable=broad-except
            print("OUTCOME echo_exc={0}".format(repr(exc)), flush=True)


if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
