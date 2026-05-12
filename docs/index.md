# warpgate Documentation

**Any peer. Any NAT.** — async NAT traversal library for Python.

Project site: <https://www.warpgate.io/>

Warpgate is a 100% open-source Python 3 library for one-shot NAT
traversal. If two computers are each behind their own routers, warpgate
establishes a direct connection between them — across home routers,
corporate firewalls, and CGNATs — without port forwarding, relay
servers, or a VPN. Eight plugins, every major OS back to Windows XP,
IPv4 and IPv6, multi-NIC, all in one library.

## When to use warpgate

- You want two programs to talk to each other directly over the internet.
- You don't control the network infrastructure (no port forwarding).
- You need to work across different NAT types (home routers, corporate
  firewalls, CGNAT, symmetric NATs paired with cones).
- You want a Python API rather than a standalone service.

## Documentation pages

- [introduction.md](introduction.md) — what NAT traversal is + how warpgate approaches it
- [quickstart.md](quickstart.md) — two peers exchanging a message in ~15 lines
- [nodes.md](nodes.md) — Node lifecycle if you skip the Gate wrapper
- [connections.md](connections.md) — `auto_connect`, `Pipe`, subscriptions
- [plugins.md](plugins.md) — the built-in traversal strategies, side by side
- [writing_a_plugin.md](writing_a_plugin.md) — build your own plugin
- [configuration.md](configuration.md) — every config knob

## Quick look

```python
import asyncio
from warpgate import Gate, TCP, peer


async def main():
    async with Gate("peer.alpha") as gate:
        link = await gate.connect(
            peer.find("peer.bravo"),
            transport=TCP,
            timeout=5.0,
        )
        async with link:
            await link.send(b"Hello world")
            async for msg in link:
                print(msg)


asyncio.run(main())
```

`Gate` derives a stable identity, registers a public nickname, and
runs `auto_connect` under the hood — racing every traversal strategy
in parallel and returning the first that succeeds.

## Platform support

CPython 3.5 → 3.13 (PyPy 3.x tested). Windows XP–11, Linux, macOS,
FreeBSD/OpenBSD, Android (Termux / Chaquopy). IPv4 and IPv6 are
first-class; multi-NIC is native.

## Installation

```bash
pip install warpgate
```

## License

MIT — every line, every sibling project. No paid tier, no telemetry,
no vendor lock-in.
