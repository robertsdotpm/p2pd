# Nodes

A `Node` is the central object in warpgate.  It manages your identity, your servers,
your connections, and the traversal engine.

> **Most users want `Gate`, not `Node`.**  `Gate` is a thin async-context
> wrapper that gives a node a stable nickname-derived identity, calls
> `node.start()` for you, exposes a `Link` per inbound peer, and tears
> everything down on `__aexit__`.  See [quickstart.md](quickstart.md)
> for the Gate-first flow.  Reach for `Node` directly when you need
> custom message callbacks, manual plugin selection, multiple nodes
> per process, or full control over the startup phase order.

## Creating a Node

```python
from warpgate import Node

node = Node()             # defaults
node = Node(port=12345)   # explicit listen port
```

### Constructor parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ifs` | list | `[]` | Pre-loaded interfaces. Auto-discovered if empty. |
| `ip` | str or list | `None` | Restrict listening to specific IP(s). |
| `port` | int | `10001` | TCP/UDP listen port. |
| `stop_rw` | socketpair | `None` | Custom stop signal pair. Auto-created if None. |
| `conf` | dict | `NODE_CONF` | Configuration dictionary. |

## Starting a Node

```python
node = await Node().start()
```

`start()` runs these phases in order:

```
1. load_network_interfaces    — discover NICs and addresses
2. load_machine_identity      — load/generate ECDSA key, derive listen port
3. load_cryptography_and_auth — set node_id from public key
4. ─── concurrent ───────────────────────────────────────────────
   initialize_system_clock    — sync NTP (if enabled)
   load_p2p_stun_clients      — load STUN clients per interface (if enabled)
   setup_router_and_signal    — connect to MQTT signal broker
   ─────────────────────────────────────────────────────────────
5. initialize_punch_coordination — log NTP skew
6. start_maintenance_tasks    — background idle-pipe cleanup
7. listen_on_ifs              — bind TCP/UDP servers on all interfaces
8. build_node_address         — serialize identity + addresses → addr_bytes
9. start_background_port_forwarding — launch UPnP task (if enabled)
10. setup_nickname_service    — initialise PNP client
11. setup_traversal_plugins   — auto-load plugins from plugins/ directory
12. finalize_port_forwarding  — await UPnP result
```

`start()` returns `self`, so you can chain: `node = await Node().start()`.

Optional parameters to `start()`:

```python
node = await Node().start(
    sys_clock=my_clock,   # reuse an existing SysClock
    out=True,             # print progress to stdout
    cout=my_logger,       # custom print function
)
```

## Node address

```python
addr_bytes = node.address()   # bytes
```

This is the serialised node address — a compact encoding of:
- ECDSA public key (for authentication)
- Machine ID (for stable port derivation)
- All interfaces: NIC IP, external IP, NAT type, port

Share it with peers out-of-band. They pass it to `auto_connect` or `node.connect()`.

```python
# Write your address to a file:
with open("my_addr.bin", "wb") as f:
    f.write(node.address())

# Another machine reads it and connects:
with open("my_addr.bin", "rb") as f:
    peer_addr = f.read()
pipe, _ = await auto_connect(node, peer_addr)
```

## Nicknames

Register a human-readable name in the PNP (Peer Name Protocol) system:

```python
full = await node.nickname("alice")
print(full)            # "alice.warpgate"
```

Names use a TLD suffix derived from the configured PNP server set
(currently `.warpgate` for the default single-server config — see
`pnp_get_tld` in `nickname.py`).  Once registered, peers can connect
by passing the full name:

```python
pipe, _ = await auto_connect(node, "alice.warpgate")
```

If the name is already registered to a different keypair, the server
rejects the put on its signature check and `node.nickname(...)` raises.

When `enable_nickname=True` (the default) the node also auto-registers
its own derived name during `start()` — see `setup_nickname_service`.

## Receiving messages

To handle messages arriving on any of the node's server pipes, register a callback:

```python
async def on_message(msg, client_tup, pipe):
    print("Got:", msg, "from:", client_tup)

node.add_msg_cb(on_message)
```

The callback fires for every message received on every server socket. `client_tup`
is `(ip, port)`, `pipe` is the server-side pipe for the connection.

## Supported address families

```python
node.supported()   # [IP4], [IP6], or [IP4, IP6]
```

Returns which address families (IPv4, IPv6) are available across all interfaces.

## Stopping a Node

```python
await node.close()
```

This cancels background tasks, closes all server sockets, shuts down STUN clients,
stops the MQTT router, and releases the process pool used by hole punching.

As a context manager:

```python
async with Node(conf=NODE_TEST_CONF) as node:
    await node.start()
    pipe, _ = await auto_connect(node, peer_addr)
    ...
# node.close() called automatically
```

## Configuration

### NODE_CONF (production defaults)

```python
NODE_CONF = {
    "reuse_addr": False,       # don't reuse ports between restarts
    "enable_upnp": True,       # try UPnP port forwarding on startup
    "sig_pipe_no": 1,          # number of MQTT signal connections per peer
    "install_path": None,      # data directory (auto-detected if None)
    "init_clock_skew": True,   # sync NTP for punch timing
    "enable_punching": True,   # load STUN clients and punch plugin
    "enable_nickname": True,   # auto-register nickname on start
    "enable_stun_clients": True,  # load STUN clients
}
```

### NODE_TEST_CONF (fast tests)

```python
NODE_TEST_CONF = {
    "reuse_addr": False,
    "enable_upnp": False,       # skip UPnP
    "sig_pipe_no": 0,           # no MQTT (no signal needed for same-machine tests)
    "install_path": None,
    "init_clock_skew": False,   # skip NTP
    "enable_punching": True,
    "enable_nickname": False,   # skip nickname registration
    "enable_stun_clients": False,  # skip STUN
}
```

Use `NODE_TEST_CONF` for unit/integration tests and for same-machine demos where
real NAT traversal isn't needed.

### Customising

```python
from aionetiface import dict_child
from warpgate.node.node_defs import NODE_TEST_CONF

MY_CONF = dict_child({"enable_upnp": True}, NODE_TEST_CONF)
node = await Node(conf=MY_CONF).start()
```

`dict_child(overrides, parent)` creates a new dict that inherits from `parent`
and applies `overrides` on top.

## Node identity and port

The listen port is derived deterministically from the machine ID:

```python
node.listen_port = field_wrap(dhash(machine_id), [10000, 60000])
```

This means the same machine always picks the same port, which helps UPnP mappings
persist between restarts. You can override it:

```python
node = Node(port=12345)
```

The machine ID itself is derived from hardware identifiers (MAC address, etc.) so it
is stable across reboots.
