# P2PD

``[Coverage >= 82%] [Python >= 3.6] [Win, Nix, BSD, Apple]``

**P2PD** is a new project aiming to make peer-to-peer networking
simple and ubiquitous. P2PD can be used either as a library or as a service.
As a library P2PD is written in Python 3 using asyncio for everything.
As a service P2PD provides a REST API on http://127.0.0.1:12333/.
The REST API is provided for non-Python languages.

P2PD offers engineers the following features:

- Multiple strategies for establishing peer-to-peer direct connections.

  - **Direct connect** = Connect to a reachable node.
  - **Reverse connect** = Tell a node to connect to you.
  - **TCP hole punching** = Simultaneous TCP connections.
  - **TURN** = Use a proxy server as a last resort.
- **Advanced NAT detection.** P2PD can detect 7 different types of NATs and
   5 different sub-types for a combined total of **35 unique NAT
   configurations.** The result is better NAT bypass.
- **Smart TCP hole punching.** The TCP hole punching algorithm has been
   designed to require minimal communication between peers to increase
   the chances of success. The algorithm supports a diverse number of
   NAT configurations for the best results possible.
- **Port forwarding (IPv4) and pin hole (IPv6.)** Automatically
   handles openning ports on the router to increase reachability.
- **IPv6 ready from day 1.** Supports IPv4 and IPv6. Introduces a new
   format for addresses that offers insight into a peer's
   NIC cards, internal network, and NAT devices.
- **A new way to do network programming.** Focuses on NICs as the
   starting point for building services. Introduces 'routes' as a
   way to provide visibility into external addresses. You can build
   services that support IPv4, IPv6, TCP, and UDP without writing
   different code for each of them.
- **Language-agnostic REST API.** You can call **/p2p/open/name/addr**
   then **/p2p/pipe/name** to turn any HTTP connection into a two-way relay
   between a peer-to-peer connection.
- **Built on open protocols.** P2PD uses **STUN** for address lookups,
   **MQTT** for signaling messages, and **TURN** for last resort proxying.
   All of these protocols have public infrastructure.

Learn how to use the software:
https://p2pd.readthedocs.io/
