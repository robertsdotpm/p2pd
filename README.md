# warpgate

**Any peer. Any NAT.** — async NAT traversal library for Python.

`[Python 3.5 → 3.13] [Windows XP–11 · Linux · macOS · BSD · Android]`

**Project site: <https://www.warpgate.io/>**

Warpgate is a 100% open-source Python 3 library for one-shot NAT traversal.
Eight plugins, every major OS back to Windows XP, IPv4 and IPv6,
multi-NIC, all in one library. No relays you have to run. No keys you
have to manage. No paid tier, ever — the code is MIT and the public
infrastructure is community-run.

## Install

```bash
python3 -m pip install warpgate
```

## Quickstart

Punch a tunnel to `peer.bravo` and echo back what we hear:

```python
# connect.py
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

Accept inbound peers across every NIC and IP family:

```python
# listen.py
import asyncio
from warpgate import Gate


async def handle(pipe, msg):
    await pipe.send(msg)


async def main():
    gate = Gate(name="echo.host")
    await gate.listen(handle)


asyncio.run(main())
```

`Gate("peer.alpha")` derives a stable identity (an ECDSA keypair
persisted under `~/aionetiface/<name>.json`) and registers the name on
the public nickname server. `peer.find(...)` resolves it and hands the
result to `gate.connect(...)`.

## Live demo

```bash
python3 -m warpgate.demo
```

Drops you into an interactive menu where you can paste a peer's nickname
or address bytes and try each traversal strategy individually.

## The plugin cascade — eight ways through

Warpgate doesn't bet on a single technique. It runs a cascade of
plugins — direct, reverse, hole-punch, probe, port-map, relay — in
whatever order you configure. The first one through wins.

| #  | Plugin                | Notes                                       |
|----|-----------------------|---------------------------------------------|
| 01 | `direct_connect`      | tcp · udp                                   |
| 02 | `reverse_connect`     | via signaling                               |
| 03 | `tcp_punch`           | TCP simultaneous open — novel algorithm     |
| 04 | `udp_punch`           | classic UDP hole punching, improved         |
| 05 | `random_probe`        | birthday-paradox bridge for symmetric NATs  |
| 06 | `upnp` / IPv6 pinhole | router-assisted                             |
| 07 | `turn`                | guaranteed fallback                         |
| 08 | *custom*              | drop in your own via the plugin API         |

A built-in NAT classifier distinguishes 7 NAT types × 5 port-delta
sub-types, so `auto_connect` only tries strategies the pair can
actually use. Peers compute a shared NTP-aligned punch instant from a
hash of the session, so coordination is one signal round-trip rather
than many.

Write your own plugin and drop it in:

```python
# my_plugin.py
from warpgate import Plugin, Pipe, TCP, register


@register(phase="direct")
class DirectTCP(Plugin):
    name = "direct_tcp"
    transport = TCP

    async def run(self, reply=None):
        route = await self.bind()
        dest = (self.dest["ip"], self.dest["port"])
        pipe = await Pipe(self.transport, dest, route).connect()
        self.result.set_result(pipe)
```

See [docs/writing_a_plugin.md](docs/writing_a_plugin.md).

## Public infrastructure

Most NAT-traversal libraries hand you a problem: stand up your own STUN,
TURN, signaling, key distribution. Warpgate ships with a public
constellation, plus a monitor that watches it. Run your own when you
need to; don't, when you don't.

- **Signaling** — [sidewire](https://github.com/robertsdotpm/sidewire)
  swaps end-to-end encrypted candidate messages over public MQTT
  brokers.
- **Discovery** — pooled community STUN servers; warpgate fans probes
  out and reconciles results to characterise the NAT in front of you.
- **Fallback** — public TURN when both sides are symmetric or behind
  locked-down corporate egress.
- **Naming** — [namebump](https://github.com/robertsdotpm/namebump)
  is an open name registry; claim a name and point peers at it instead
  of juggling public keys.
- **Monitoring** — [dogdorm](https://github.com/robertsdotpm/dogdorm)
  probes the public infrastructure constantly and keeps an updated
  server list, so warpgate skips servers that are down.

## Compatibility

| OS                  | Min version              | Support |
|---------------------|--------------------------|---------|
| Windows             | XP SP3                   | tier 1  |
| Linux               | kernel 2.6               | tier 1  |
| macOS               | 10.9+                    | tier 1  |
| FreeBSD / OpenBSD   | recent                   | tier 1  |
| Android             | via Termux / Chaquopy    | tier 2  |

| Runtime / network  | Versions                  | Notes        |
|--------------------|---------------------------|--------------|
| CPython            | 3.5 → 3.13                | primary      |
| PyPy               | 3.x                       | tested       |
| IPv4               | all NAT classes           | first-class  |
| IPv6               | incl. pinhole / RA        | first-class  |
| Multi-NIC          | bind-per-interface        | native       |

Stdlib + ecdsa only at runtime for the core paths — no native deps to
compile.

## The stack

Warpgate is one project in a family. Each piece does one thing well,
ships independently, and runs on the same public infrastructure. Use
them together, or pull just the one you need.

- **warpgate** (this repo) — the cascade. One-shot NAT traversal across
  eight plugins; glue for everything below.
- [aionetiface](https://github.com/robertsdotpm/aionetiface) — async
  networking with first-class multi-interface support.
- [sidewire](https://github.com/robertsdotpm/sidewire) — signaling over
  public MQTT brokers, topic-per-peer.
- [namebump](https://github.com/robertsdotpm/namebump) — open name
  registry with per-IP quotas.
- [dogdorm](https://github.com/robertsdotpm/dogdorm) — liveness
  monitoring for the public infrastructure.

## Documentation

Full docs: <https://p2pd.readthedocs.io/>

The same pages live under [`docs/`](docs/) in this repo:

- [introduction.md](docs/introduction.md) — what NAT traversal is + how warpgate approaches it
- [quickstart.md](docs/quickstart.md) — two peers exchanging a message
- [nodes.md](docs/nodes.md) — Node lifecycle if you want to skip the Gate wrapper
- [connections.md](docs/connections.md) — `auto_connect`, `Pipe`, subscriptions
- [plugins.md](docs/plugins.md) — the built-in traversal strategies, side by side
- [writing_a_plugin.md](docs/writing_a_plugin.md) — build your own plugin
- [configuration.md](docs/configuration.md) — every config knob

## License

MIT — every line, every sibling project. No paid tier, no telemetry, no
vendor lock-in. See [LICENSE](LICENSE).
