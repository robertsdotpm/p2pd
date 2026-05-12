# Plugins

Warpgate's connection layer is plugin-based.  Each plugin implements one
traversal technique.  `auto_connect` walks them in *phase* order and
runs every valid combo concurrently — first winner wins.

## Phases and ordering

```text
direct ─► punch ─► spray ─► relay
```

| Phase | When it runs | Plugins shipped |
| --- | --- | --- |
| `direct` | Always tried first | `direct_connect`, `reverse_connect` |
| `punch` | If `direct` doesn't win | `tcp_punch` |
| `spray` | If `punch` doesn't win | `udp_punch`, `random_probe` |
| `relay` | Last resort | `turn` |

Within each phase, every valid `(plugin × address-family × route-type)`
combo for the pair is launched concurrently.  As soon as any combo
returns a working `Pipe`, the rest are cancelled and later phases are
skipped.

## Built-in plugins

### `direct_connect`

Plain TCP connect to the peer's advertised address.

```text
Alice ──TCP connect──► Bob:listen_port
```

Works when:

- Bob has a public IP, or
- Bob's router opened a port via UPnP, or
- Both peers are on the same LAN, or
- Both peers are on the same machine (loopback alias path).

Speed: instant.  Phase: `direct`.

### `reverse_connect`

Alice signals Bob over MQTT: *"please connect to me using direct_connect"*.
Bob runs his `direct_connect` against Alice.

```text
Alice ──signal──► Bob (ConMsg{plugin_name="direct_connect"})
Bob   ──TCP connect──► Alice
```

Use when Alice is reachable but Bob is not.  Phase: `direct`.

### `tcp_punch`

TCP simultaneous-open through both NATs.  Both peers compute a shared
NTP-aligned punch instant + a per-bucket port-prediction set, then
fire `connect()` calls at each other's predicted ports at the agreed
time.  Crossing SYNs create NAT state on both sides; one of the
predicted 4-tuples lands an `ESTABLISHED` connection.

Boundary-time rendezvous (overlap window B and B+1) absorbs the
~5% bucket-fork rate that comes from MQTT signal latency.

Works for: full-cone, address-restricted, port-restricted NATs.
Doesn't work for: symmetric NATs (port allocation isn't predictable
enough — use `random_probe` instead).

Phase: `punch`.  Internal timeout: 180 s.

### `udp_punch`

Same protocol exchange as `tcp_punch`, but the actual fire-and-verify
phase runs in-process over UDP — no subprocess, no SYN/SYN-ACK
sequencing, no half-open SYN cap.  Lower overhead and works on
platforms where TCP simul-open is unreliable (XP cross-NAT, etc.).

Phase: `spray`.  Internal timeout: 150 s.

### `random_probe`

Tailscale-style birthday-paradox bridge for cone↔symmetric pairs.
The cone side fires N UDP probes at random destination ports on the
symmetric peer's external IP; the symmetric side fires one probe
from each of N source-port-distinct sockets at the cone peer's known
`(ext_ip, ext_port)`.  With `N=256` each, ~63% of attempts produce a
4-tuple that bridges both NATs.

The plugin reuses `tcp_punch`'s boundary algorithm purely for *timing*
synchronisation.  UDP only.

Phase: `spray`.  Internal timeout: 150 s.

### `turn`

TURN (Traversal Using Relays around NAT) — relay all traffic through
a public TURN server.  Last-resort fallback when no direct path
exists.

```text
Alice ──UDP──► TURN server ──UDP──► Bob
```

Works for every NAT type because traffic is relayed.  Adds 2× the
RTT to the relay server.  Phase: `relay`.  Internal timeout: 60 s.

## Auxiliary plugins

These don't participate in `auto_connect` directly — they expose
specific signal-channel operations that other plugins or the node
itself uses internally.

- **`get_addr` / `return_addr`** — refresh a peer's address by asking
  them over the signal channel.  Used by `resolve_pnp_addr` when the
  cached PNP record looks stale.
- **`fan_out`** — runs N candidate plugins in parallel against the
  same peer, picking the first one that establishes.  Used by
  `auto_connect`'s phase machinery internally.

All three are registered with `phase=None`, so `auto_connect`'s
phase walker skips them.

## Plugin lookup

The `plugin_registry` is built at import time by every
`@register(phase=...)` decorator.  `node.start()` calls
`load_plugins(node)` which:

1. Imports every `src/warpgate/traversal/plugins/<name>/main.py` (so all
   built-in `@register` decorators fire).
2. Calls `discover()` to import any external plugins advertised under
   the `warpgate.strategies` entry-point group.
3. Walks the registry and either:
   - Calls `cls.setup(node)` and uses the returned factory as the
     per-attempt builder, or
   - Uses the class itself as the builder.
4. Registers each plugin's `proto_messages` with the
   `TraversalManager`'s wire-format dispatcher.

## Plugin lifecycle per connection attempt

```text
auto_connect(node, peer_addr)
       │
       ▼
build (plugin × af × route_type) combos
       │
       ▼
TraversalManager.attempt_plugin(...)
       │
       ├─ install: set_routing, set_context, set_inbound_pipes, set_send_signal_msg
       │
       └─ run_plugin(plugin)
              │
              ├─ await asyncio.wait_for(plugin.run(reply), timeout=plugin.timeout)
              │
              └─ on exception: plugin.result.set_result(None)        (fast-fail)

plugin.result resolves to a Pipe on success, None on failure
```

## What's available on `self` inside `run()`

See [writing_a_plugin.md](writing_a_plugin.md) for the full table of
attributes and the resolution contract for `self.result`.

## Running a single named plugin

To pin `auto_connect` to one strategy, use `node.connect` directly:

```python
plugin = await node.connect(
    af=IP4,
    route_type=NIC_BIND,
    pnp_addr=peer_addr,
    plugin_name="direct_connect",
)
pipe = await asyncio.wait_for(plugin.result, timeout=10)
```
