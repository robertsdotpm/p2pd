# P2PD

`[Python ≥ 3.5] [macOS · Linux · Windows · BSD · Android]`

[![Demo image](https://github.com/robertsdotpm/p2pd/blob/main/demo_small.gif?raw=true)](https://github.com/robertsdotpm/p2pd/blob/main/demo_large.gif)

[Watch demo on Asciinema](https://asciinema.org/a/EhADOwnoPt5KBiQDbwR69bNHS)

P2PD is a Python library for peer-to-peer NAT traversal. If two computers
are each behind their own routers, P2PD opens a direct connection between
them — across home routers, corporate firewalls, and CGNATs — without
port-forwarding, relay servers, or a VPN.

The project is split into four sibling packages:

- **p2pd** (this repo) — the high-level peer API + traversal plugins.
- [aionetiface](https://github.com/robertsdotpm/aionetiface) — interface
  enumeration, address handling, and the asyncio socket primitives.
- [namebump](https://github.com/robertsdotpm/namebump) — public-access KVS
  used as the peer-name registry.  Anyone can register; per-IP quotas keep
  it honest.
- [sidewire](https://github.com/robertsdotpm/sidewire) — MQTT-based
  signaling used by the punch and reverse-connect plugins.

## Install

```bash
python3 -m pip install p2pd
```

On non-Windows hosts, make sure `gcc` and `python3-devel` (or your distro's
equivalent) are installed first.

## Quickstart

The smallest useful program — Alice listens, Bob dials in by name:

```python
import asyncio
from p2pd import Gate, peer

async def alice():
    async with Gate("alice") as gate:
        async for link in gate.listen():
            async for msg in link:
                await link.send(b"echo:" + msg)

async def bob():
    async with Gate("bob") as gate:
        link = await gate.connect(peer.find("alice"))
        await link.send(b"hi")
        print(await link.recv())          # b"echo:hi"

asyncio.run(asyncio.gather(alice(), bob()))
```

`Gate("alice")` derives a stable identity (an ECDSA keypair persisted under
`~/aionetiface/<name>.json`) and registers `alice.p2p` on the public
nickname server.  `peer.find("alice")` returns a handle that
`gate.connect(...)` resolves and dials.

If you need finer control (custom message callbacks, per-NIC binds,
manual plugin selection), drop down to the `Node` API — see
[docs/nodes.md](docs/nodes.md).

## Live demo

```bash
python3 -m p2pd.demo
```

Drops you in an interactive menu where you can paste a peer's nickname or
address bytes and try each traversal strategy individually
(direct, reverse, tcp_punch, udp_punch, random_probe, turn).

## What's in the box

- **Six traversal strategies** that `auto_connect` races concurrently:
  - `direct_connect` — plain TCP to a reachable peer.
  - `reverse_connect` — ask the peer to dial back through the signal channel.
  - `tcp_punch` — TCP simultaneous-open hole punching for cone + restricted NATs.
  - `udp_punch` — UDP hole punching with port-prediction (lower overhead than TCP punch).
  - `random_probe` — Tailscale-style birthday-paradox bridge for cone↔symmetric pairs.
  - `turn` — public TURN relay as last-resort fallback.
- **NAT classifier** — distinguishes 7 NAT types × 5 port-delta sub-types,
  so `auto_connect` only tries strategies the pair can actually use.
- **Boundary-time rendezvous** — both peers compute a shared NTP-aligned
  punch instant from a hash of the session, so coordination is one signal
  round-trip instead of multiple.
- **Multi-interface, every AF, every route type** — LAN, WAN, and
  per-node loopback paths are exercised in parallel; first winner wins.
- **Plugin registry** — drop a `@register`-decorated `Plugin` subclass
  anywhere on the Python path and `auto_connect` picks it up.  See
  [docs/writing_a_plugin.md](docs/writing_a_plugin.md).
- **UPnP IGD + IPv6 pinhole** — opportunistically opens ports on the
  router for direct reachability.
- **Stdlib + ecdsa only** at runtime for the core paths — no native deps
  for the user to compile.

## Documentation

Full docs: <https://p2pd.readthedocs.io/>

The same pages live under [`docs/`](docs/) in this repo:

- [introduction.md](docs/introduction.md) — what NAT traversal is + how P2PD approaches it
- [quickstart.md](docs/quickstart.md) — two peers exchanging a message
- [nodes.md](docs/nodes.md) — Node lifecycle if you want to skip the Gate wrapper
- [connections.md](docs/connections.md) — `auto_connect`, `Pipe`, subscriptions
- [plugins.md](docs/plugins.md) — the built-in traversal strategies, side by side
- [writing_a_plugin.md](docs/writing_a_plugin.md) — build your own plugin
- [configuration.md](docs/configuration.md) — every config knob

## License

See [LICENSE](LICENSE).
