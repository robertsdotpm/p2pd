Daemons
========

In the :doc:`pipes` section I showed some examples of how servers can be built
using the `pipe_open` function. Such an approach is fine if you only want 
to use one protocol or address type. But real-world servers
may need to run on multiple routes, address, and interfaces. The
Daemon class offers some convenience methods for servers.

.. HINT::
    It's easy to use the Daemon class. Simply inherit from Daemon in a
    child class. Your class should have a msg_cb function for incoming messages.
    The class can store any state you need.

async def add_listener(self, proto, route)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Add a new service to the daemon. Proto is TCP or UDP. Route is a Route
object returned from a route pool or the route function from Interface.

async def listen_all(self, proto, port, nic):
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Listen on all addresses on a machine. The need for the NIC parameter is
as a standard function prototype for consistency. When you listen to
all addresses the service may be accessible from the Internet
and will be accessible on the LAN and loopback interface.

async def listen_loopback(self, proto, port, nic):
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Start listening on the loopback address. Whether it binds to IP4 / IP6
is based on the supported address families for the NIC you provide.
This function is useful for creating servers you want to make
accessible on just that computer. P2PD's own rest_api and toxid
use this method.

async def listen_local(self, proto, port, nic):
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For IPv6 this function listens on a NICs link-local addresses. For
IPv4 it will listen on the NICs private addresses. For the latter
-- if there are forwarding rules setup or the node is not behind a
NAT -- this could mean making the service public. 