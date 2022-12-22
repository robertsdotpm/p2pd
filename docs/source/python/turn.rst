TURN client
============

TURN is a protocol used for relaying TCP and UDP end-points between peers.
In P2PD I've implemented an asynchronous, IPv4 / IPv6, TURN client.
It has the same interface as a pipe and supports awaits + callbacks. But the
TURN client uses UDP over TCP. It provides reliable delivery but it does not provide ordered delivery (yet?)

The reason why UDP was implemented and not TCP is due to the way TCP works and
what TURN is designed to be used for. P2PD already implements **direct connect, 
reverse connect, and TCP hole punching**. If all of these fail it means that
there is very little chance of establishing a TCP connection with a peer.
But believe it or not: this is the assumption made in the TURN protocol. The TURN server makes an outgoing connection to a service (which must be reachable.)

The TURN spec mentions that this could be combined with **TCP hole punching
for clients**. But this is not feasible because no synchronization mechanism for making connections has been offered in the TURN protocol -- at least none that
I've seen. It would have been unlikely to work given that punching needs to
be synchronized down to the milisecond. All of this could have been avoided
if TURN were designed around reverse connections. So that both parties
behind NATs could simply connect to the server and setup channels. But TURN doesn't seem to offer this possibility.

.. note::

    Fun fact: **TURN is the worst protocol I've ever had the displeasure of working
    with**. It manages to make a simple proxy server look like a moonlanding mission.
    I don't even know how they managed to over-engineer the protocol to such a
    high-level. I don't think I could manage to fuck something up that badly even
    if I was trolling. True story.

UDP is a little better
^^^^^^^^^^^^^^^^^^^^^^^^

When you go through the TURN protocol as a client you get allocated a special 
'relay address' from the server that another peer can use to route messages to
you. As far as I know this only works for UDP. But importantly it offers a
reverse connect design which is capable of bypassing NATs.

UDP is a better choice as a last resort because it is 'connectionless.'
It doesn't require the receipt of a handshake. The NAT will simply let
through packets to a UDP socket as long as that socket address has already sent
data to the destination. So UDP hole punching is easier than TCP.

The downside is... it's UDP. It offers no reliable delivery or sequencing. But a few
hacks add delivery back in. It wouldn't be possible to add sequencing, too.
Though I have not done this for now. That was a lot of text so let's look at some code.

.. code-block:: python

    from p2pd import *

    # Network interface details.
    i = await Interface().start()
    r = await i.route().bind()

    # Address of a TURN server.
    dest = await Address(
        "p2pd.net",
        3478
    ).res(r)

    # Sync message callback -- do something here if you like.
    # Can be async too.
    msg_cb = lambda msg, client_tup, pipe: print(msg)

    # Implement the TURN protocol for UDP send / recv.
    client = TURNClient(
        turn_addr=dest,
        turn_user=None,
        turn_pw=None,
        turn_realm=b"p2pd.net",
        route=r,
        msg_cb=msg_cb
    )

    # Wait for authentication and relay address allocation.
    await async_wrap_errors(
        client.start()
    )
    client.subscribe(SUB_ALL)

    # Send a message to ourselves.
    await client.send(b"hello, world!", await client.relay_tup_future)
    # You should see the message printed.

    # Alternatively the pub-sub API is available since we called subscribe.
    out = await client.recv()
    print(out)

    # Cleanup.
    await client.close()

