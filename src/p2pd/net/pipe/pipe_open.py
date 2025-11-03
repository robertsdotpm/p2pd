"""
- pipe_open allows multiple encoding forms to be used for the IP
field. But bytes is a little unclear. Is it the raw bytes of
an IP address or is it a human-readable IP in ASCII? I
decided to default to the latter otherwise devs. But you
can still pass in ints or IPRanges to use raw IPs. With
ints just make sure there is a route alongside it because
the address family is needed to disambiguate whether the
int is a short IPv6 or an IPv4.

- theres a bug on ancient operating systems (Windows Vista)
where await sock_event with wait_for can crash the event loop.
The fix has been merged in >= 3.7.5 which also works on Vista.
I wasn't even able to get Python 3 to run on XP so for now it
isn't supported. Trying to merge Python fixes for older OSes
isn't a priority so these users should be told to upgrade
Python versions if they get bugs with the event loop.

https://bugs.python.org/issue34795
"""


import asyncio
from ...utility.utils import *
from ..net_utils import *
from ..bind import *
from .pipe_events import *
from ..address import Address
from ..ip_range import IPRange
from ..address import *
from ..asyncio_patches import *
from .pipe_tcp_events import *
from ..socket import *

p2pd_fds = set()

"""
In the spirit of unix a 'pipe' is an protocol and destination
agnostic way to send data. It supports TCP & UDP: cons & servers.
It supports using IPv4 and IPv6 destination addresses.
You can pull data from it based on a regex pattern.
You can execute code on new messages or connection disconnects.
"""
async def pipe_open(proto, dest=None, route=None, sock=None, msg_cb=None, up_cb=None, conf=NET_CONF):
    # Check proto.
    if proto not in (UDP, TCP, RUDP):
        raise Exception("Transport proto for pipe_open not supported.")

    # Patch _select if needed.
    if sys.platform == 'win32':
        if SelectSelector._select != patched_select:
            SelectSelector._select = patched_select

    # Covers the case where passed in route is an Interface.
    # In that case -- just use first route at first supported AF.
    if route is not None and route.__name__ == "Interface":
        nic = route
        route = nic.route()

    # Load dest as an Address.
    af = route.af if route is not None else None
    if dest is not None:
        # IP:port pair -> Address.
        if isinstance(dest, (list, tuple)):
            ip, port = dest

            # Supports int, bytes.
            # Due to lack of preceding 0s
            # int can be ambiguous for AFs tho.
            if isinstance(ip, int):
                cidr = CIDR_WAN if af is None else af_to_cidr(af)
                ip = IPRange(ip, cidr=cidr)

            # Support IP as an IPR.
            if isinstance(ip, IPRange):
                ip = ipr_norm(ip)

            # Load AF of any entered IPs.
            dest = Address(
                ip,
                port,
                conf=conf
            )

    # If no route is set assume default interface, first route.
    if route is None:
        from ...nic.interface import Interface

        # Load internal addresses.
        i = await Interface()

        # Bind to route 0.
        route = await i.route(af)

    # Ensure route is bound.
    if not route.resolved:
        await route.bind()

    # Ensure address instance is resolved.
    if isinstance(dest, Address):
        # Resolve unresolved addresses.
        if not dest.resolved:
            await dest.res(route)

        # Select compatible address.
        dest = dest.select_ip(route.af)
        
    # Build the base protocol object.
    pipe_events = None
    try:
        # Get event loop reference.
        if conf["loop"] is not None:
            loop = conf["loop"]()
        else:
            loop = asyncio.get_event_loop()

        # Build socket bound to specific interface.
        if sock is None:
            sock = await socket_factory(
                route=route,
                dest_addr=dest,
                sock_type=UDP if proto == RUDP else proto,
                conf=conf
            )

            #print(sock)

            # Check if sock succeeded.
            if sock is None:
                log("Could not allocate socket.")
                return None
            else:
                p2pd_fds.add(sock)

            # Connect socket if TCP.
            if proto == TCP and dest is not None:
                # Set non-blocking.
                sock.settimeout(0)
                sock.setblocking(0)

                # Connect the socket task.
                con_task = asyncio.create_task(
                    loop.sock_connect(
                        sock, 
                        dest.tup
                    )
                )
                
                # Wait for connection, async style.
                await asyncio.wait_for(con_task, conf["con_timeout"])
                    
        # Make sure bind port is set (and not zero.)
        route.bind_port = sock.getsockname()[1]

        # Return the sock instead of base proto.
        if conf["sock_only"]:
            return sock

        # Main protocol instance for routing messages.
        #if base_proto is None:
        pipe_events = PipeEvents(sock=sock, route=route, loop=loop, conf=conf)
        pipe_events.proto = proto

        # Add message handler.
        if msg_cb is not None:
            pipe_events.add_msg_cb(msg_cb)

        # Start processing messages for UDP.
        if proto in [UDP, RUDP]:
            #print("loop for create dg endpoint", loop)
            transport, _ = await create_datagram_endpoint(
                loop,
                lambda: pipe_events,
                sock=sock
            )

            await pipe_events.stream_ready.wait()
            pipe_events.stream.set_handle(transport, client_tup=None)
            if dest is not None:
                pipe_events.set_endpoint_type(TYPE_UDP_CON)
            else:
                pipe_events.set_endpoint_type(TYPE_UDP_SERVER)

        # Install default ack builder and handler.
        # Now it is poorman's TCP ;_____; but still no ordering.
        if proto == RUDP:
            pipe_events.set_ack_handlers(
                is_ack=pipe_events.stream.is_ack,
                is_ackable=pipe_events.stream.is_ackable
            )

        # Start processing messages for TCP.
        if proto == TCP:
            # Add new connection handler.
            if up_cb is not None:
                pipe_events.add_up_cb(up_cb)

            # Listen server.
            if dest is None:
                # Start router for TCP messages.
                server = await create_tcp_server(
                    sock=sock,
                    pipe_events=pipe_events,
                    loop=loop,
                    conf=conf
                )

                # Make the server start serving requests.
                assert(server is not None)
                pipe_events.set_tcp_server(server)

                # Saving the task is apparently needed
                # or the garbage collector could close it.
                if hasattr(server, "serve_forever"):
                    server_task = asyncio.create_task(
                        async_wrap_errors(
                            server.serve_forever()
                        )
                    )
                    
                    pipe_events.set_tcp_server_task(server_task)

                pipe_events.set_endpoint_type(TYPE_TCP_SERVER)

            # Single connection.
            if dest is not None:
                # Enable SSL on this socket.
                if conf["use_ssl"]:
                    # Some security options are disabled for simplicity.
                    # TODO: explore this more.
                    ssl_context = ssl.create_default_context()
                    #ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')
                    #ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                    ssl_context.check_hostname = False 
                    ssl_context.verify_mode = ssl.CERT_NONE
                    server_hostname = ""
                else:
                    ssl_context = False
                    server_hostname = None

                # base_proto.set_handle(writer, sock.getpeername())
                await loop.create_connection(
                    protocol_factory=lambda: pipe_events,
                    sock=sock,
                    ssl=ssl_context,
                    server_hostname=server_hostname
                )

                # Set transport handle.
                await pipe_events.stream_ready.wait()
                pipe_events.stream.set_handle(pipe_events.transport, dest.tup)
                pipe_events.set_endpoint_type(TYPE_TCP_CON)

        # Set dest if it's present.
        if dest is not None:
            pipe_events.stream.dest = dest
            pipe_events.stream.set_dest_tup(dest.tup)

            # Queue all messages for convenience.
            if msg_cb is None:
                pipe_events.subscribe(SUB_ALL)

        # Register pipes, msg callbacks, and subscriptions.
        return pipe_events
    except Exception as e:
        log_exception()

        """
        Enables closing the socket if an error occurs.
        Don't remove this conditional code as it's
        needed to support TCP hole punching.
        """
        if conf["do_close"]:
            if sock is not None:
                log(fstr("closing socket. {0}", (sock.getsockname(),)))
                sock.close()
            
            if pipe_events is not None:
                log("closing bas proto")
                await pipe_events.close()

async def pipe_utils_workspace():
    from .interface import Interface

    i = await Interface()
    dest = ("google.com", 80)
    r = await i.route(IP4)
    p = await pipe_open(TCP, dest, r)
    print(p.sock)
    await p.close()

if __name__ == "__main__":
    async_test(pipe_utils_workspace)