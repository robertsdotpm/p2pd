# Configuration

## Node configuration

Pass a configuration dictionary to `Node(conf=...)`.

### Full reference

```python
NODE_CONF = {
    # Socket options
    "reuse_addr": False,

    # UPnP
    "enable_upnp": True,

    # Signaling
    "sig_pipe_no": 1,

    # Storage
    "install_path": None,

    # NTP clock sync (needed for hole punching)
    "init_clock_skew": True,

    # Hole punching
    "enable_punching": True,

    # Nickname service
    "enable_nickname": True,

    # STUN clients (needed for hole punching)
    "enable_stun_clients": True,
}
```

### Option details

#### `reuse_addr` (bool, default `False`)

Sets `SO_REUSEADDR` on server sockets. Useful during development to avoid "address
already in use" errors when restarting quickly. Leave `False` in production to avoid
hiding socket errors.

#### `enable_upnp` (bool, default `True`)

At startup, try to add a UPnP port-forwarding rule on the local router. This lets
other nodes connect to you without hole punching or TURN. Adds a few seconds to
startup time.

Set to `False` if your router doesn't support UPnP, you know you're on open internet,
or you want faster startup.

#### `sig_pipe_no` (int, default `1`)

Number of MQTT signal connections to keep open per peer. Higher values improve
reliability but use more connections.

Set to `0` for same-machine tests where no signal channel is needed.

#### `install_path` (str or None, default `None`)

Directory for storing the signing key, machine ID, and PID lock files.
Auto-detected from the system if `None` (typically `~/.local/share/aionetiface/`).

#### `init_clock_skew` (bool, default `True`)

Synchronise the local clock against NTP at startup. Required for hole punching
(both peers must agree on the punch time). Adds ~1-2s to startup.

Set to `False` when testing or when hole punching is disabled.

#### `enable_punching` (bool, default `True`)

Load the `punch` plugin and its STUN clients. Disable to skip hole punching
entirely (faster startup, useful if you only have open-internet nodes).

Automatically disables `enable_stun_clients` if set to `False`.

#### `enable_nickname` (bool, default `True`)

Register this node's address under its `node_id` in the PNP naming service at
startup, and keep it renewed. Disable to skip the registration step.

#### `enable_stun_clients` (bool, default `True`)

Load STUN TCP clients for each interface at startup. Required for hole punching.
Loading takes a few seconds as it probes multiple STUN servers.

## Preset configurations

### NODE_CONF — production defaults

```python
from p2pd.node.node_defs import NODE_CONF
```

Everything enabled. Use for deployed nodes that need to traverse real NATs.
Startup takes 5–15 seconds.

### NODE_TEST_CONF — fast tests

```python
from p2pd.node.node_defs import NODE_TEST_CONF
```

```python
NODE_TEST_CONF = {
    "reuse_addr": False,
    "enable_upnp": False,
    "sig_pipe_no": 0,
    "install_path": None,
    "init_clock_skew": False,
    "enable_punching": True,
    "enable_nickname": False,
    "enable_stun_clients": False,
}
```

Minimal set that starts a node almost instantly. Use for:
- Unit and integration tests
- Same-machine examples
- Anything that doesn't need real NAT traversal

### Custom configuration

Extend a base preset with `dict_child`:

```python
from aionetiface import dict_child
from p2pd.node.node_defs import NODE_TEST_CONF

# Enable signaling for cross-machine tests while keeping everything else minimal
CROSS_MACHINE_TEST_CONF = dict_child(
    {"sig_pipe_no": 1, "init_clock_skew": False},
    NODE_TEST_CONF,
)
```

`dict_child(overrides, parent)` creates a new dict where `overrides` take
precedence over `parent`. It does not modify either input.

## Net configuration

`Node` also inherits `NET_CONF` from `aionetiface` for socket-level settings:

```python
NET_CONF = {
    "recv_timeout": 2,      # default recv() timeout in seconds
    "max_qsize": 200,       # max messages in a subscription queue
    ...
}
```

These are merged with the node conf automatically. You can override them in your
custom conf dict.

## Plugin configuration

Each plugin declares its own `conf` dict on the class:

```python
# tcp_punch/main.py
@register(phase="punch")
class PunchPlugin(Plugin):
    name = "tcp_punch"
    conf = {"timeout": 180}

# turn/main.py
@register(phase="relay")
class TURNPlugin(Plugin):
    name = "turn"
    conf = {"timeout": 60}
```

`timeout` is the number of seconds `TraversalManager` waits for one
`plugin.run()` call before cancelling it.  The demo's outer await on
`plugin.result` is `plugin.timeout + 10` (see `demo/menu.py`).

To override a plugin timeout at runtime, replace its installed entry
on the manager:

```python
node.traversal.install_plugin("tcp_punch", {
    "class": PunchPlugin,
    "timeout": 60,
})
```

## Environment

p2pd stores data in:

| Data | Location |
|------|----------|
| ECDSA signing key | `{install_path}/signing_key.pem` |
| Machine ID | derived from NIC MAC addresses |
| PID lock files | `{install_path}/{af}_{proto}_{port}_{ip}_pid.txt` |

The `install_path` defaults to the aionetiface install root, typically
`~/.local/share/aionetiface/` on Linux.
