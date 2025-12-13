"""
When you're writing server code you are constantly restarting
the process and making changes. This can lead to processes
staying open / lingering in the background that are still listening
on the same port. When doing hacks to reuse ports rapidly for
testing it can lead to very unexpected behavior. Like the
background server (that you don't realize still exists) ends
up stealing all the packets and then you waste hours wndering
why your networking code isn't working.

TODO: Better zombie process detection.
"""

from ..utility.utils import *
from .address import *
from .net_utils import *
from ..nic.interface import *
from .pipe.pipe import *
from ..install import *

DAEMON_CONF = dict_child({
    "reuse_addr": True
}, NET_CONF)

"""
For TCP-servers this code attempts a positive connection with a
a desired server endpoint to listen on. Obviously such code
doesn't apply to UDP which is connectionless.
"""
async def is_serv_listening(proto, listen_route):
    # UDP is connectionless.
    # A Pipe socket doesn't mean its open.
    if proto == UDP:
        return False

    # Destination address details for serv.
    listen_ip = listen_route.bind_tup()[0]
    listen_port = listen_route.bind_tup()[1]
    if not listen_port:
        return False

    # Route to connect to serv.
    route = listen_route.interface.route(listen_route.af)
    await route.bind()

    # If listen was on all then the dest IP will be wrong.
    if listen_ip in VALID_ANY_ADDR:
        listen_ip = "localhost"

    # Try make pipe to the server socket.
    dest = (listen_ip, listen_port)
    try:
        pipe = await Pipe(proto, dest, route).connect()
        await pipe.close()
        return True
    except Exception:
        return False

"""
Used to detect if daemons have uncleanly exited in which case
the listen socket is being used and allowing it to be used again
even with "tricks" would lead to unexpected results (usually data loss)
as packets end up being routed to the zombie server process over the
socket started for the new server.
"""
def get_serv_lock(af, proto, serv_port, serv_ip, install_path):
    # Make install dir if needed.
    try:
        pathlib.Path(install_path).mkdir(parents=True, exist_ok=True)
    except Exception:
        log_exception()

    # Main path files.
    af = "v4" if af == IP4 else "v6"
    proto = "tcp" if proto == TCP else "udp"
    serv_ip = serv_ip.replace(":", "_")
    serv_ip = serv_ip.replace(".", "_")
    pidfile_path = os.path.realpath(
        os.path.join(
            install_path,

            # TODO: use hashes here instead..
            fstr(
                "{0}_{1}_{2}_{3}_pid.txt",
                (af, proto, serv_port, serv_ip,)
            )
        )
    )

    # TODO: use a more portable approach that's safer.
    try:
        import fasteners
        return fasteners.InterProcessLock(pidfile_path)
    except Exception:
        return None

"""
A coroutine func receives a server (pipe) for every server
being listened on in a daemon class.
"""
async def for_server_in_daemon(daemon, func):
    tasks = []
    for af in VALID_AFS:
        for proto in [TCP, UDP]:
            for port in daemon.servers[af][proto]:
                for ip in daemon.servers[af][proto][port]:
                    server = daemon.servers[af][proto][port][ip]
                    tasks.append(
                        async_wrap_errors(
                            func(server)
                        )
                    )
    
    await asyncio.gather(*tasks, return_exceptions=True)

class Daemon():
    def __init__(self, conf=DAEMON_CONF):
        # Special net conf for daemon servers.
        self.conf = conf

        # Used for storing PID lock files.
        self.install_path = get_p2pd_install_root()

        # AF: proto: port: ip: pipe_events.
        self.servers = {
            IP4: {
                TCP: {}, UDP: {}
            }, 
            IP6: {
                TCP: {}, UDP: {}
            }, 
        }

    # On message received (placeholder.)
    async def msg_cb(self, msg, client_tup, pipe):
        print("Specify your own msg_cb in a child class.")
        print(fstr("{0} {1}", (msg, client_tup,)))
        await pipe.send(msg, client_tup)

    # On connection success (placeholder.)
    # Ran when a connection is first created for a client.
    # Just like connection_made in protocol classes.
    def up_cb(self, msg, client_tup, pipe):
        pass

    """
    Can be used to manually add a pipe to listen on for this daemon.
    Used by some of the convienence functions like
    listen_all and listen_local.
    """
    async def add_listener(self, proto, route):
        # Ensure route is bound.
        assert(route.resolved)

        """
        In socket programming bind can be passed a port value of 0
        meaning "let the OS choose" or specify a value manually.
        When you specify manually you're not guaranteed to get
        a free, non-conflicting port and need to detect error
        states where the port is already used (maybe by previous
        runs of this very code that were killed badly.)
        """
        bind_port = route.bind_port

        # Check if server is already listening.
        lock = None
        ip, port = route.bind_tup()[:2]
        if bind_port:
            # Detect zombie servers.
            lock = get_serv_lock(route.af, proto, port, ip, self.install_path)
            if lock is not None:
                if not lock.acquire(blocking=False):
                    error = fstr("{0}:{1} zombie pid", (proto, bind_str(route),))
                    raise Exception(error)

            # A simple TCP con is made to TCP servers to check if it's
            # still listening before binding.
            is_listening = await async_wrap_errors(
                is_serv_listening(proto, route)
            )

            # If it is then raise exception.
            if is_listening:
                error = fstr("{0}:{1} listen conflict.", (proto, bind_str(route),))
                raise Exception(error)
        
        # Start a new server listening.
        try:
            pipe = await Pipe(proto, None, route, conf=self.conf).connect(
                self.msg_cb, self.up_cb
            )
        except Exception:
            raise

        assert(pipe is not None)

        """
        When servers are closed the OS can put the socket in TIME_WAIT
        which prevents rebinding to the same port for several minutes.
        This raises errors if you restart the same process with the
        same listen ports and generally makes testing a nightmare.
        This is a hack to allow TIME_WAIT sockets to be used.
        """
        avoid_time_wait(pipe)

        # Only one instance of this service allowed.
        if bind_port:
            pipe.proc_lock = lock

        """
        A zero bind port means the OS will choose a port. So the
        assigned port is looked up to record the quad-tuple
        (AF, proto, port, IP) for the service bellow.
        In such a case no proc_lock file is created since
        additional invocations of the same code (with a zero port)
        are guaranteed to get non-conflicting ports.
        """
        if not bind_port:
            _, port = pipe.sock.getsockname()

        # Store the server pipe.
        self.servers[route.af][proto].setdefault(port, {})
        self.servers[route.af][proto][port][ip] = pipe
        return (port, pipe)

    """
    There's a special IPv6 sock option to listen on
    all address types but its not guaranteed.
    Hence I use two sockets based on supported stack.
    """
    async def listen_all(self, proto, port, nic):
        outs = []
        for af in nic.supported():
            route = nic.route(af)
            await route.bind(ips="*", port=port)
            outs.append(
                await async_wrap_errors(
                    self.add_listener(proto, route)
                )
            )

        return strip_none(outs)

    """
    Localhost here is translated to the right address
    depending on the AF supported by the NIC.
    The bind_magic function takes care of this.
    """
    async def listen_loopback(self, proto, port, nic):
        outs = []
        for af in nic.supported():
            route = nic.route(af)
            await route.bind(ips="localhost", port=port)
            outs.append(
                await async_wrap_errors(
                    self.add_listener(proto, route)
                )
            )

        return strip_none(outs)

    """
    Really no way to do this with IPv4 without adding
    something like a basic firewall. But IPv6 has the
    link-local addresses and UNL. Perhaps a basic
    firewall could be a future feature.
    """
    async def listen_local(self, proto, port, nic, limit=1):
        outs = []
        for af in nic.supported():
            total = 0

            # Supports private IPv4 addresses.
            if af == IP4:
                nic_iprs = []
                for route in nic.rp[af]:
                    # For every local address in the route table.
                    for nic_ipr in route.nic_ips:
                        # Only bind to unique addresses.
                        if nic_ipr in nic_iprs:
                            continue
                        else:
                            nic_iprs.append(nic_ipr)
                            total += 1

                        # Avoid bind limit.
                        if limit is not None:
                            if total > limit:
                                break

                        # Don't modify the route table directly.
                        # Note: only binds to first IP.
                        # An IPR could represent a range.
                        local = copy.deepcopy(route)
                        ips = ipr_norm(nic_ipr)
                        await local.bind(ips=ips, port=port)

                        # Save add output.
                        outs.append(
                            await async_wrap_errors(
                                self.add_listener(proto, local)
                            )
                        )

            # Supports link-locals and unique local addresses.
            if af == IP6:
                route = nic.route(af)
                for link_local in route.link_locals:
                    # Avoid bind limit.
                    if limit is not None:
                        if total > limit:
                            break

                    # Bind to link local.
                    local = nic.route(af)
                    ips = ipr_norm(link_local)
                    await async_wrap_errors(
                        local.bind(ips=ips, port=port)
                    )

                    # Save listener output.
                    outs.append(
                        await async_wrap_errors(
                            self.add_listener(proto, local)
                        )
                    )

        return strip_none(outs)

    """
    msg_cb functions are run whenever a pipe / listener receives
    a message -- its protocol is described at the top.
    This func adds a new msg_cb to the list of msg_cbs for
    every listener / pipe registered in this daemon.
    """
    def add_msg_cb(self, msg_cb):
        async def func(server):
            server.add_msg_cb(msg_cb)

        asyncio.create_task(
            for_server_in_daemon(self, func)
        )

    async def close(self):
        async def func(server):
            await server.close()

        await for_server_in_daemon(self, func)

async def daemon_rewrite_workspace():
    serv = None
    try:
        nic = await Interface("wlx00c0cab5760d")
        serv = Daemon()

        await serv.listen_local(TCP, 1337, nic)
        print(serv.pipes)

        while 1:
            await asyncio.sleep(1)
    except Exception:
        await serv.close()
        log_exception()


if __name__ == "__main__":
    async_test(daemon_rewrite_workspace)
