# P2PD

``[Coverage >= 82%] [Python >= 3.6] [Mac, Win, Nix, BSD, Android]``

Welcome to the new release of **P2PD.** P2PD is a library for doing
peer-to-peer networking in Python. This release offers a new methodology
for improving connectivity between hosts. It works on private networks, across
the Internet, and even in-between nodes on the same machine.

Tens of thousands of lines of code have been updated. Most modules have been refactored or re-written. The protocol has been replaced and now supports encryption; TCP punching now works with IPv6; The STUN client supports hundreds more servers; UPnP is less noisy (and actually works); Networking code has been refreshed to reduce errors; Core connectivity methods have been redesigned (and tested quite thoroughly.)

The new release also includes a simple domain system that offers open,
authenticated, registration-free, domain names. The feature is free
to use (though some resource limits apply.)

## Installation

On non-windows systems make sure you have gcc and python3-devel installed.

   python3 -m pip install p2pd

## Demo

For an interactive demo type this in your terminal.

  python3 -m p2pd.demo

## Documentation

https://p2pd.readthedocs.io/

## Features

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
   handles opening ports on the router to increase reachability.
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
- **Minimal dependencies.** Most of the code in P2PD uses the Python
  standard library to improve portability and reduce packaging issues.
- **Built on open protocols.**
   **STUN** for address lookups, **MQTT** for signaling messages, and
   **TURN** for last resort message relaying.
   All of these protocols have public infrastructure.
