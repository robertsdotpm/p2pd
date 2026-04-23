# Writing a Plugin

This guide walks through building a custom traversal plugin from scratch.

A runnable version of the example plugin lives at
[tests/test_docs_plugin.py](../tests/test_docs_plugin.py).

## What a plugin does

A plugin is responsible for one thing: getting a `Pipe` between two nodes.
It has access to:
- Both nodes' address maps (IPs, NAT types, ports)
- A signal channel to exchange coordination messages with the peer
- The local NIC/interface for binding

When it succeeds, it resolves `self.result` with the `Pipe`. If it can't make a
connection, it just returns without setting the result.

## Anatomy of a plugin

Every plugin is a subclass of `TraversalPlugin` that overrides `run()`:

```python
from p2pd.traversal.traversal_plugin import TraversalPlugin

class MyPlugin(TraversalPlugin):
    async def run(self, reply=None) -> None:
        # Make a Pipe here.
        # If successful: self.result.set_result(pipe)
        pass

PLUGIN_CLASS = MyPlugin
```

The `run()` method may be called more than once if the plugin participates in a
multi-round signal exchange (like `punch`). The `reply` argument is the signal
message that triggered this call, or `None` on the first invocation.

## Example 1: direct TCP connection

The simplest possible plugin — just connect:

```python
# plugins/my_direct/main.py
import asyncio
from aionetiface import TCP, Pipe, log_exception
from p2pd.traversal.traversal_plugin import TraversalPlugin


class MyDirectPlugin(TraversalPlugin):
    async def run(self, reply=None) -> None:
        dest = (str(self.dest_info["ip"]), self.dest_info["port"])
        route = await self.nic.route(self.af).bind()

        try:
            pipe = await Pipe(TCP, dest, route).connect()
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()
            return

        if pipe is not None:
            self.result.set_result(pipe)


PLUGIN_CLASS = MyDirectPlugin
```

Key attributes available in `run()`:

| Attribute | Type | Description |
|-----------|------|-------------|
| `self.af` | `IP4` or `IP6` | Address family to use |
| `self.nic` | Interface | Local network interface |
| `self.dest_info["ip"]` | str | Best destination IP (pre-selected by route_type) |
| `self.dest_info["port"]` | int | Peer's listen port |
| `self.dest_info["nat"]` | IPRange | Peer's NAT info |
| `self.src_info` | dict | Same fields for local node |
| `self.route_type` | NIC_BIND or EXT_BIND | Whether to use LAN or WAN path |
| `self.same_machine` | bool | True if both endpoints are the same machine |

## Example 2: signal-coordinated connection

Plugins can exchange control messages over the signal channel before connecting.
This is how `reverse_connect` works: it asks the peer to initiate the connection.

```python
# plugins/my_reverse/main.py
import asyncio
from aionetiface import TCP, Pipe, log_exception
from p2pd.traversal.traversal_plugin import TraversalPlugin
from p2pd.protocol.proto_msg import ConMsg


class MyReversePlugin(TraversalPlugin):
    """Ask the peer to connect to us instead."""

    async def run(self, reply=None) -> None:
        # Build a signal message telling the peer to connect to us using
        # the "direct_connect" plugin (they call DirectConnect.run()).
        msg = ConMsg()
        msg.meta.plugin_name = "direct_connect"

        # Register an inbound slot BEFORE sending the signal to avoid a
        # race condition: the peer might connect before we register.
        self.register_inbound()

        # Send the signal over MQTT.
        await self.send_signal_msg(msg)

        # Wait for the inbound connection to arrive.
        con = await self.wait_for_inbound()
        self.result.set_result(con)


PLUGIN_CLASS = MyReversePlugin
```

### The signal exchange in detail

```
MyReversePlugin.run()             DirectConnect.run() on peer
       │                                    │
       ├─ register_inbound()                │
       │   (registers future in             │
       │    node.inbound_pipes)             │
       │                                    │
       ├─ send_signal_msg(msg) ─────────────► recv_signal_msg()
       │                                    │    ▼
       │                                    ├─ routes to DirectConnect
       │                                    │
       │                            ┌───────┤ DirectConnect.run()
       │                            │       │  connects to our address
       │   inbound_pipes[plugin_id] │       │  sends CON_ID_MSG + plugin_id
       │   future resolves ◄────────┘       │
       │                                    │
       ├─ wait_for_inbound() returns pipe   │
       │                                    │
       └─ result.set_result(pipe)           └─ result.set_result(pipe)
```

### Signal message types

| Class | Use |
|-------|-----|
| `ConMsg` | Ask peer to connect to us (used by reverse_connect) |
| `GetAddr` | Ask peer for their current address |
| `ReturnAddr` | Reply to GetAddr with address bytes |
| `PunchMsg` | Exchange NAT port predictions for hole punching |
| `TURNMsg` | TURN relay coordination |

All signal messages have a `msg.meta.plugin_name` field that routes the message
to the correct plugin instance on the receiving side.

## Example 3: multi-round exchange

For protocols that need multiple round trips (like punch), `run()` is called once
per incoming signal message:

```python
class MyNegotiatePlugin(TraversalPlugin):
    def __init__(self):
        super().__init__()
        self.round = 0

    async def run(self, reply=None) -> None:
        self.round += 1

        if self.round == 1:
            # First call: send our offer
            msg = build_offer_msg()
            msg.meta.plugin_name = "my_negotiate"
            await self.send_signal_msg(msg)
            # run() returns; waiting for peer's reply

        elif self.round == 2:
            # Second call: peer replied with reply.payload
            peer_data = reply.payload
            pipe = await connect_using(peer_data)
            if pipe is not None:
                self.result.set_result(pipe)
```

The `TraversalManager` calls `run(reply=msg)` whenever a signal message arrives
with `plugin_name` matching this plugin's name.

## Plugin configuration

A plugin can declare default configuration:

```python
PLUGIN_CONF = {
    "timeout": 30,    # how long auto_connect waits for this plugin
}
```

`timeout` is the only field the framework uses directly. Other fields are available
to the plugin as custom state if you store them at the factory level.

## Factory plugins

For plugins that need shared state across all instances (like shared STUN clients
or a process pool), use `setup_plugin` instead of `PLUGIN_CLASS`:

```python
# plugins/my_heavy/main.py

class MyHeavyPlugin(TraversalPlugin):
    def __init__(self):
        super().__init__()
        self.shared_resource = None  # filled in by factory

    async def run(self, reply=None) -> None:
        result = await use(self.shared_resource)
        self.result.set_result(result)


class MyHeavyFactory:
    def __init__(self, shared_resource):
        self.shared_resource = shared_resource

    def build_plugin(self):
        plugin = MyHeavyPlugin()
        plugin.shared_resource = self.shared_resource
        return plugin

    async def close(self):
        await self.shared_resource.close()


async def setup_plugin(node):
    """Called once at node startup. Returns factory or None to skip plugin."""
    resource = await initialize_something_expensive()
    factory = MyHeavyFactory(resource)
    node.resources.register(factory)   # ensures factory.close() is called on shutdown
    return factory
```

The factory's `build_plugin()` method is called by the traversal manager each time a
new connection attempt starts.

Return `None` from `setup_plugin` to disable the plugin conditionally:

```python
async def setup_plugin(node):
    if not node.conf.get("enable_my_plugin", True):
        return None   # plugin not loaded
    ...
```

## Auto-discovery conventions

Place your plugin in `src/p2pd/traversal/plugins/<name>/main.py`. The loader checks
for either `PLUGIN_CLASS` or `setup_plugin` at module level.

The plugin name defaults to the directory name but can be overridden:

```python
PLUGIN_NAME = "my_custom_name"
```

Plugin directories are loaded in sorted alphabetical order.

## Installing a plugin at runtime

You can install a plugin outside of the auto-loader:

```python
node.traversal.install_plugin("my_plugin", {
    "class": MyPlugin,
    "timeout": 15,
})
```

After installing, it is available to `auto_connect` and `node.connect`.

## Testing your plugin

Use `NODE_TEST_CONF` so you don't need a live MQTT connection for simple tests.
For signal-based plugins you'll need `sig_pipe_no=1`.

```python
# tests/test_my_plugin.py
import asyncio
import unittest
from aionetiface import dict_child
from p2pd import Node
from p2pd.node.node_defs import NODE_TEST_CONF
from p2pd.node.auto_connect import auto_connect

MY_TEST_CONF = dict_child({"sig_pipe_no": 1}, NODE_TEST_CONF)


class TestMyPlugin(unittest.IsolatedAsyncioTestCase):
    async def test_my_plugin_connects(self):
        alice = await Node(conf=MY_TEST_CONF).start()
        bob   = await Node(conf=MY_TEST_CONF).start()
        try:
            # Install only your plugin so auto_connect uses it exclusively
            for node in (alice, bob):
                # remove other plugins if needed
                node.traversal.plugin_loaders.clear()
                node.traversal.install_plugin("my_plugin", {"class": MyPlugin})

            pipe, _ = await auto_connect(alice, bob.address())
            self.assertIsNotNone(pipe)
        finally:
            await alice.close()
            await bob.close()
```

## Checklist

- [ ] Subclass `TraversalPlugin`
- [ ] Override `async def run(self, reply=None)`
- [ ] Call `self.result.set_result(pipe)` on success
- [ ] Handle `OSError`, `ConnectionError`, `asyncio.TimeoutError` — just return, don't raise
- [ ] Register inbound *before* sending signals to avoid race conditions
- [ ] Place in `plugins/<name>/main.py` with `PLUGIN_CLASS` or `setup_plugin`
- [ ] Set `PLUGIN_CONF = {"timeout": N}` for the right timeout
- [ ] Write a test using `NODE_TEST_CONF`
