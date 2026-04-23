# p2pd Documentation

p2pd is a Python library for peer-to-peer NAT traversal. If two computers are each
behind their own routers, p2pd establishes a direct connection between them — even
through symmetric NATs — without requiring port forwarding or a VPN.

## When to use p2pd

- You want two programs to talk to each other directly over the internet
- You don't control the network infrastructure (no port forwarding)
- You need to work across different NAT types (home routers, corporate firewalls, CGNAT)
- You want a Python API rather than a standalone service

## Documentation

| Page | What you'll learn |
|------|-------------------|
| [Introduction](introduction.md) | What NAT traversal is and how p2pd approaches it |
| [Quickstart](quickstart.md) | Two nodes exchanging messages in ~20 lines of code |
| [Nodes](nodes.md) | Starting, configuring, and stopping a Node |
| [Connections](connections.md) | How auto_connect works and what a Pipe gives you |
| [Plugins](plugins.md) | The six built-in traversal strategies |
| [Writing a Plugin](writing_a_plugin.md) | Developer guide: build your own traversal strategy |
| [Configuration](configuration.md) | All configuration options explained |

## Quick look

```python
import asyncio
from p2pd import Node
from p2pd.node.auto_connect import auto_connect

async def main():
    node = await Node().start()
    print("My address:", node.address())

    # Share node.address() with another computer out-of-band.
    # Then connect:
    pipe, plugin = await auto_connect(node, their_address_bytes)
    await pipe.send(b"hello")
    await node.close()

asyncio.run(main())
```

## Platform support

Python 3.5+, Linux, macOS, Windows, BSD, Android.

## Installation

```
pip install p2pd
```
