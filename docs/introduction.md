# Introduction

## The problem: NAT traversal

Most computers on the internet sit behind a NAT (Network Address Translation) router.
Your laptop's IP address is something like `192.168.1.5`; your router has the real
public IP, say `203.0.113.42`. When your laptop opens a connection *outward*, the
router translates the source address. But when something outside wants to connect *to*
your laptop directly, it has no idea where to route that packet — the router blocks it.

```
Internet
    │
    │ 203.0.113.42 (public IP)
┌───┴────────────────────┐
│   Router / NAT         │
└───┬────────────────────┘
    │ 192.168.1.0/24 (private)
    │
    ├── 192.168.1.5  (your laptop)
    └── 192.168.1.8  (your phone)
```

When two people are each behind their own NAT, a direct connection is hard:

```
Person A                         Person B
192.168.1.5                      10.0.0.3
    │                                │
    │ NAT A                          │ NAT B
    │ 203.0.113.42                   │ 198.51.100.7
    │                                │
    └──────── Internet ──────────────┘

A wants to connect to B. B's packets reach NAT B, not B's laptop.
```

## How p2pd solves it

p2pd tries multiple strategies in parallel and uses whichever works first:

```
                    ┌──────────────┐
                    │ Signal Server│  (MQTT broker — public)
                    │   (relay)    │
                    └──────┬───────┘
                 signals   │   signals
          ┌────────────────┴────────────────┐
          │                                  │
     ┌────┴─────┐                      ┌─────┴────┐
     │  Node A  │◄────── direct ───────►  Node B  │
     └──────────┘    (if NATs allow)   └──────────┘
```

The strategies, tried concurrently:

1. **Direct connect** — just try TCP. Works if one side has an open port.
2. **Reverse connect** — ask the other side to connect to us.
3. **Hole punching** — both sides open the NAT simultaneously so packets get through.
4. **TURN relay** — fall back to relaying traffic through a public server.

## Key concepts

### Node

A `Node` is your local endpoint. It listens for incoming connections, manages its
identity, and knows how to reach other nodes.

```
Node
 ├── identity (ECDSA key pair, node_id)
 ├── address (addr_bytes — shareable with peers)
 ├── nickname (optional: registered name in the PNP system)
 ├── servers (one TCP/UDP socket per interface × address family)
 └── traversal (the plugin engine that establishes connections)
```

### Address

A node's address is a compact byte string encoding:
- The node's public key (for authentication)
- All its network interfaces and their IPs/NAT types
- The listen port

You exchange this address with peers out-of-band (paste it in a chat, put it in a file,
etc.). p2pd also offers a nickname service so you can register a human-readable name.

### Pipe

A `Pipe` is a connected channel between two nodes. Once you have one, you call
`send` and `recv` just like a socket.

```python
pipe, plugin = await auto_connect(node, dest_addr)
await pipe.send(b"hello world")
data = await pipe.recv(SUB_ALL)
```

### Plugin

Plugins are the traversal strategies. Each plugin tries to establish a connection in
its own way. `auto_connect` runs them all in parallel and returns the first winner.
You can also invoke a specific plugin by name if you know what you need.

### Signal channel

Plugins coordinate by exchanging small control messages over a public MQTT broker
(the "signal channel"). These are just handshake packets — your actual data flows
directly between the two nodes.

## What p2pd is NOT

- It is not a P2P networking framework (like libp2p or BitTorrent's DHT). It only
  handles the *connectivity* part — getting a socket open between two machines.
- It does not encrypt your data. Use TLS/DTLS or your own encryption on top of a Pipe.
- It is not a VPN.
