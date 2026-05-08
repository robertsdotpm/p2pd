# p2pd Documentation

p2pd is a Python library for peer-to-peer NAT traversal.  If two
computers are each behind their own routers, p2pd establishes a direct
connection between them — across home routers, corporate firewalls,
and CGNATs — without port forwarding, relay servers, or a VPN.

## When to use p2pd

- You want two programs to talk to each other directly over the internet.
- You don't control the network infrastructure (no port forwarding).
- You need to work across different NAT types (home routers, corporate
  firewalls, CGNAT, symmetric NATs paired with cones).
- You want a Python API rather than a standalone service.

## Documentation pages

- [introduction.md](introduction.md) — what NAT traversal is + how p2pd approaches it
- [quickstart.md](quickstart.md) — two peers exchanging a message in ~15 lines
- [nodes.md](nodes.md) — Node lifecycle if you skip the Gate wrapper
- [connections.md](connections.md) — `auto_connect`, `Pipe`, subscriptions
- [plugins.md](plugins.md) — the built-in traversal strategies, side by side
- [writing_a_plugin.md](writing_a_plugin.md) — build your own plugin
- [configuration.md](configuration.md) — every config knob

## Quick look

```python
import asyncio
from p2pd import Gate, peer
from aionetiface import SUB_ALL


async def echo(link):
    async for msg in link:
        await link.send(b"echo:" + msg)


async def alice():
    async with Gate("alice") as gate:
        await gate.listen(echo)


async def bob():
    async with Gate("bob") as gate:
        pipe, _ = await gate.connect(peer.find("alice"))
        pipe.subscribe(SUB_ALL)
        await pipe.send(b"hi")
        print(await pipe.recv(SUB_ALL))       # b"echo:hi"


asyncio.run(asyncio.gather(alice(), bob()))
```

`Gate` derives a stable identity, registers a public nickname, and
runs `auto_connect` under the hood — racing every traversal strategy
in parallel and returning the first that succeeds.

## Platform support

Python 3.5+, Linux, macOS, Windows, BSD, Android.

## Installation

```bash
pip install p2pd
```
