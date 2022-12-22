# Examples

At a low-level: P2PD can be used for general async network programming. At a high-level - it can be used for peer-to-peer
networking.

## Low level examples

- stun_client.py -- STUN client using pipes.
- turn_client.py -- TURN client using pipes.
- upnp.py -- Port forwarding using pipes.

## High level examples

- p2p_node.py -- Node server for writing custom P2P protocols.
- p2p_pipe.py -- For making 'p2p' connections to other nodes.
- tcp_punch.py -- Does port prediction and TCP hole punching.
- rest_api.py -- A REST API server for doing p2p I/O.
