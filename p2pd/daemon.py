from .address import *
from .interface import *
from .base_stream import *

DAEMON_CONF = dict_child({
    "reuse_addr": True
}, NET_CONF)

"""
interface = listen on all addresses given by af
bind = may take specific addresses to listen to -- listen only on af addresses
targets = [interface, bind, ...]

protocols to use for the server.
protos = [TCP, UDP]

list of ports to listen on. may contain ranges.
ports = [n, [x, y], ...]

called on new messages from a stream.
process the message.
f = lambda msg, stream: ...
"""
class Daemon():
    def __init__(self, interfaces=None, conf=DAEMON_CONF):
        self.conf = conf
        self.servers = []
        self.restricted_proto = None
        self.interfaces = interfaces or []
        self.iface_lookup = {}
        for iface in self.interfaces:
            self.iface_lookup[iface.name] = iface
        self.rp = None

    def restrict_proto(self, proto):
        self.restricted_proto = proto

    """
    Overwritten by children.
    msg = data received from server
    client_tup = (remote ip, remote port) of client socket.
    pipe = BaseProto object
    """
    def msg_cb(self, msg, client_tup, pipe):
        # Overwritten by inherited classes.
        print("This is a default proto msg_cb! Specify your own in a child class.")
        pass
    
    async def _listen(self, target, port, proto, msg_cb=None):
        msg_cb = msg_cb or self.msg_cb

        # Protocol not supported.
        if self.restricted_proto is not None:
            if self.restricted_proto != proto:
                raise Exception("That protocol is not supported for this server.")
    
        # Convert Bind to routes.
        routes = []

        # Target is already a route - record.
        if isinstance(target, Route):
            routes.append(target)
        else:
            # Route inherits Bind so this would also be True for
            # a Route object. Check Route first to avoid this.
            if isinstance(target, Bind):
                if target.af == AF_ANY:
                    af_list = VALID_AFS
                else:
                    af_list = [target.af]

                # Make a route for each AF.
                for af_val in af_list:
                    # Interface does not support AF.
                    # None Interface if using loopback.
                    if target.interface is not None:
                        if af_val not in target.interface.what_afs():
                            log("> bind inst: af_val not in iface afs")
                            continue


                        # Gets the route associated with the bind IP.
                        route = await bind_to_route(target)

                        # Record route.
                        routes.append(route)

        # Start server on every address.
        assert(len(routes))
        for route in routes:
            await route.bind(port)
            log('starting server {}:{} p={}, af={}'.format(
                route.bind_ip(),
                port,
                proto,
                route.af
            ))

            # Link route to a route pool.
            # So it can do cool tricks.
            if self.rp is not None:
                route.link_route_pool(self.rp[route.af])

            # Save list of servers.
            listen_task = pipe_open(route, proto, msg_cb=msg_cb, conf=self.conf)
            base_proto = await listen_task
            if base_proto is None:
                raise Exception("Could not start server.")

            self.servers.append([ route, proto, base_proto, listen_task ])
            return base_proto
    
    # [[Bound, proto], ...]
    # Allows for servers to be bound to specific addresses and transports.
    # The other start method is more general.
    async def listen_specific(self, targets, msg_cb=None):
        msg_cb = msg_cb or self.msg_cb
        targets = [targets] if not isinstance(targets, list) else targets
        for listen_info in targets:
            # Unpack.
            bound, proto = listen_info

            # Start server.
            await self._listen(
                target=bound,
                proto=proto,
                port=bound.bind_port,
                msg_cb=msg_cb
            )

    # Start all the servers listening.
    # All targets are started on the same list of ports and protocols.
    # A more general version of the above function.
    async def listen_all(self, targets, ports, protos, af=AF_ANY, msg_cb=None, error_on_af=0):
        msg_cb = msg_cb or self.msg_cb
        targets = [targets] if not isinstance(targets, list) else targets
        routes = []
        for target in targets:
            # Convert Interface to route.
            if isinstance(target, Interface):
                # List of AFs to use.
                if af == AF_ANY:
                    af_list = target.what_afs()
                else:
                    af_list = [af]

                # If Interface doesn't support AF
                # do we throw an error or skip it?
                for af_val in af_list:
                    if af_val not in target.what_afs():
                        log("> listen all af not in what afs")
                        if error_on_af:
                            e = "IF {} doesn't support AF {}".format(
                                target.id,
                                af
                            )
                            raise Exception(e)

                # Build routes from afs + interface.
                for af_val in af_list:
                    if not len(target.rp[af_val].routes):
                        continue

                    # First route in pool for that AF.
                    # Makes a copy of the route.
                    route = target.route(af_val)
                    routes.append(route)

            # Convert RoutePool to Routes.
            # Makes new instances of the routes.
            if isinstance(target, RoutePool):
                routes += target[:]

            # Route.
            if isinstance(target, Route):
                routes.append(
                    copy.deepcopy(target)
                )

        # Targets are Interfaces to listen on or Bind objects.
        for route in routes:
            # Loop over all the listen ports.
            for port_info in ports:
                # Ports may be a single port or a range.
                if type(port_info) == list:
                    port_start, port_end = port_info
                else:
                    port_end = port_start = port_info

                # Treat ports as a range.
                for port in range(port_start, port_end + 1):
                    # Start the server on bind address, port, and proto.
                    for proto in protos:
                        route = copy.deepcopy(route)
                        await self._listen(route, port, proto, msg_cb)

                        # Bind to additional link-local for IPv6.
                        if route.af == IP6:
                            try:
                                route = copy.deepcopy(route)
                                route = await route.bind(port=port, ips=route.nic())
                                await self._listen(route, port, proto, msg_cb)
                            except Exception:
                                pass
                                # May already be started -- ignore.

        return self

    async def close(self):
        for server_info in self.servers:
            _, _, server, _ = server_info
            await server.close()

        self.servers = []

if __name__ == "__main__": # pragma: no cover
    pass
    #async_test(test_tcp_punch)