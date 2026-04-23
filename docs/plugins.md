# Plugins

p2pd uses a plugin system to try multiple connection strategies. Each plugin implements
one traversal technique. `auto_connect` runs compatible plugins concurrently and returns
the first winner.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        auto_connect                          │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │direct_connect│  │reverse_connect│  │      punch        │  │
│  │             │  │              │  │                   │  │
│  │  plain TCP  │  │ ask peer to  │  │ hole-punch NATs   │  │
│  │  connection │  │ connect back │  │ simultaneously    │  │
│  └─────────────┘  └──────────────┘  └───────────────────┘  │
│                                                              │
│  If all fail ──► turn (relay, last resort)                   │
└─────────────────────────────────────────────────────────────┘

Supporting plugins (not in auto_connect):
  get_addr    — ask peer for their current address
  return_addr — respond to get_addr
```

## Plugin selection

`auto_connect` skips plugins in `SKIP_IN_AUTO = {"turn", "get_addr", "return_addr"}`.
For the remaining plugins it builds all valid combinations:

```
for af in [IP4, IP6]:
    for route_type in [NIC_BIND, EXT_BIND]:
        for plugin in [direct_connect, reverse_connect, punch]:
            if both nodes support af:
                if nodes have distinct addresses for route_type:
                    add combo
```

NIC_BIND (local path) combos are tried before EXT_BIND (WAN path).

## direct_connect

The simplest strategy: open a TCP connection directly to the peer's address.

```
Alice ──TCP connect──► Bob's public IP:port
```

Works when:
- Bob is not behind NAT (has a public IP)
- Bob's router has port forwarding configured
- UPnP opened a port on Bob's router
- Both nodes are on the same LAN

Fails when:
- Bob is behind a NAT with no port forwarding

**Speed:** instant (no coordination needed)  
**Reliability:** high when applicable, not widely applicable behind symmetric NATs

## reverse_connect

Alice asks Bob (via the signal channel) to connect to Alice instead.

```
Alice ──signal──► Bob: "please connect to me"
Bob  ──TCP connect──► Alice's address
```

Works when:
- Alice has an open port but Bob does not
- Complementary to direct_connect: if Alice can't connect to Bob, maybe Bob can connect to Alice

The plugin sends a `ConMsg` signal with `plugin_name="direct_connect"`, which causes
Bob's `direct_connect` plugin to attempt the connection.

**Speed:** slightly slower (one signal round trip + connection)  
**Reliability:** same as direct_connect but roles reversed

## punch

Attempts TCP hole punching: both sides open their NAT simultaneously by sending
packets at an agreed time. The crossed packets create NAT state entries on both sides,
allowing subsequent packets through.

```
Alice ──signal──► Bob: "punch at T+5s, my predicted ports: [50001, 50002, ...]"
Bob   ──signal──► Alice: "punch at T+5s, my predicted ports: [60001, 60002, ...]"

At T+5s, both sides send TCP SYN packets to each other's predicted ports.
One of them lands in the NAT state window and a connection forms.
```

This plugin uses:
- STUN clients to probe NAT behaviour and predict port allocations
- NTP clock sync to coordinate the simultaneous punch time
- A subprocess (`start_punching_process`) to hit the time window precisely

Works for:
- Full-cone NATs
- Address-restricted NATs
- Port-restricted NATs

Does not work for:
- Symmetric NATs (port allocation is unpredictable)

Requires: `enable_punching=True` and `enable_stun_clients=True` in the conf.

**Speed:** slow (multiple STUN probes + NTP sync + punch delay ~5s)  
**Reliability:** ~70-90% success for cone NATs, low for symmetric NATs  
**Config:** `PLUGIN_CONF = {"timeout": 40}`

## turn

TURN (Traversal Using Relays around NAT) relays all traffic through a public server.
This is the last-resort fallback.

```
Alice ──────────────► TURN server ──────────────► Bob
       (relayed)                    (relayed)
```

Works for every NAT type because all traffic goes through the relay server.

**Speed:** adds latency equal to 2× the distance to the relay server  
**Reliability:** very high (only fails if relay is unavailable)  
**Cost:** traffic goes through public infrastructure; use only as fallback  
**Config:** `PLUGIN_CONF = {"timeout": 20}`

Note: `auto_connect` tries TURN only after all other strategies fail, up to
`turn_limit` interface pairs.

## get_addr / return_addr

These are utility plugins for address resolution, not connection establishment.

`get_addr` sends a signal to the peer asking for their current address.
`return_addr` responds with the current address bytes.

These are used internally by `resolve_pnp_addr` to refresh stale cached addresses.
You typically don't use them directly.

## Plugin lifecycle

```
install_plugin("direct_connect", conf)
       │
       ▼
attempt_plugin(src_map, dest_map, sig_pipe, plugin_name, af, route_type)
       │
       ├── validate combo (addresses match, distinct IPs, etc.)
       │
       ├── build plugin instance (plugin_loaders["direct_connect"]())
       │
       ├── configure: set_addrs, set_routing, set_context, set_inbound_pipes
       │
       └── schedule run() as a background task
              │
              ▼
         plugin.result  ← asyncio.Future
              │
    resolves to Pipe on success, or stays pending on failure
```

## Plugin state

All plugins inherit from `TraversalPlugin`:

```python
class TraversalPlugin:
    result     = asyncio.Future()  # resolves to Pipe on success
    plugin_id  = str               # random 15-char ID for inbound routing
    af         = IP4 | IP6         # address family in use
    src_info   = dict              # {"ip": ..., "nat": ..., "ext": ..., "nic": ...}
    dest_info  = dict              # same fields for peer
    nic        = Interface         # local NIC object
    route_type = NIC_BIND | EXT_BIND
```

## Auto-discovery

Plugins are discovered automatically at startup. The loader scans
`src/p2pd/traversal/plugins/` for subdirectories that contain `main.py` and
expose either:

- `PLUGIN_CLASS` — a class that will be instantiated per connection attempt, or
- `async def setup_plugin(node)` — for plugins that need node-level shared state
  (like shared STUN clients or a process pool)

See [Writing a Plugin](writing_a_plugin.md) for how to create your own.
