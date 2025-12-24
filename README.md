# P2PD

``[Python >= 3.5] [Mac, Win, Nix, BSD, Android]``

[![Demo image](https://github.com/robertsdotpm/p2pd/blob/main/demo_small.gif?raw=true)](https://github.com/robertsdotpm/p2pd/blob/main/demo_large.gif)

[Watch demo on Asciinema](https://asciinema.org/a/EhADOwnoPt5KBiQDbwR69bNHS)

Update 3: I've been in the process of cleaning up all the code here. There's over
20k lines and while it was once fine for a "demo" actually using it was quite horrible.
I decided to take the step of split the project up into different packages.

[aionetiface](https://github.com/robertsdotpm/aionetiface) -- will now handle just the networking. This is Python3 package that brings interface support and proper address
handling to Python. There's more to it than that -- but the code is working well.

[namebump](https://github.com/robertsdotpm/namebump) -- this is a new kind of
public-access key-value store. It's a KVS that anyone can use. The database has
resource limits per IP and names that aren't used expire over time.

[dogdorm](https://github.com/robertsdotpm/dogdorm) -- this is a system for monitoring
public servers used by peer-to-peer software (like STUN, TURN, MQTT, etc.) It
is used to determine the reliability of public infrastructure so that software can
be both decentralized and reliable.

Finally, there will be a yet unreleased NAT traversal work that depends on all of
the above packages. It features a brand new algorithm for doing hole punching that
is vastly improved over anything else I've previously seen. I will probably release
this as a new package and deprecate this one because the name for P2PD isn't that
allusive. ETA on everything finished I'm not sure -- but releasing the above
to show you what I've already done.

Here's a teaser so far of a very beautiful hole punching algorithm that depends
on math and cryptography rather than complex network protocols:

[punch.py](https://raw.githubusercontent.com/robertsdotpm/p2pd/refs/heads/folders_windows/examples/punch.py)

---

Update 2: P2P stuff is broken at the moment. I'm slowly fixing it and will build
better tooling for testing in the future.
Update: Great news everyone! I am over my burn out and feel inspired to hack again. Some things I want to do now:

- Improve docs and make videos so people know more what the project is about. People are still confused I think.
- Improve how interfaces are done in this library -- abstract them out more. This will make the software more robust to failure in the event that interface detection fails.
- More tests for loading nodes -- try to speed that up as people's time is very limited.
- Lets take on the mobile network now and break symmetric NATs. I'm in a rare position now to do that as I'm now behind a CGNAT.
- **Contributors:** You don't even have to write code to help me with this project. I'd love for people who are interested in the project to let me test connectivity from their network. I'm sure we can learn and improve the software.
- I have an idea for something new that could be extremely useful if I can get it to work. You'll have to speculate what it is for nao ;)

**P2PD is a library for doing NAT traversal in Python.** If you're behind a router and want to connect to another computer behind a router the software is for that.
It accomplishes that by using multiple techniques that it tries to get a connection going. I think there was some confusion before with people thinking that this
library was for making P2P networks (like Bitcoins P2P network.) Yes, you --could-- do that, but you would still have to write the bootstrapping code yourself
(I should prob rename ths library at some point tbh, sorry.) The core feature of this library is to make direct connectivity just work regardless of the
relationship between two computers. The computers could even be on the same LAN and the software is still smart enough to facilitate that.

The new release includes a simple domain system that offers open,
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
- **Multi-interface.** Focuses on NICs as the starting point
   for building services. Introduces 'routes' as a
   way to provide visibility into external addresses. You can build
   services that support IPv4, IPv6, TCP, and UDP without writing
   different code for each of them.
- **Minimal dependencies.** Most of the code in P2PD uses the Python
  standard library to improve portability and reduce packaging issues.
- **Built on open protocols.**
   **STUN** for address lookups, **MQTT** for signaling messages, and
   **TURN** for last resort message relaying.
   All of these protocols have public infrastructure.
