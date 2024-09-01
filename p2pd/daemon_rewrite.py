from .utils import *
from .address import *
from .interface import *
from .pipe_utils import *
from .install import *

DAEMON_CONF = dict_child({
    "reuse_addr": True
}, NET_CONF)

async def is_serv_listening(proto, listen_route):
    # Destination address details for serv.
    listen_ip = listen_route.bind_tup()[0]
    listen_port = listen_route.bind_tup()[1]
    if not listen_port:
        return False

    # Route to connect to serv.
    route = listen_route.interface.route(listen_route.af)
    await route.bind()

    # Try make pipe to the server socket.
    dest = await Address(listen_ip, listen_port, route)
    pipe = await pipe_open(proto, dest, route)
    if pipe is not None:
        await pipe.close()
        return True
    
    return False

def get_serv_lock(af, proto, serv_port, serv_ip):
    # Make install dir if needed.
    try:
        install_root = get_p2pd_install_root()
        pathlib.Path(install_root).mkdir(parents=True, exist_ok=True)
    except:
        log_exception()

    # Main path files.
    af = "v4" if af == IP4 else "v6"
    proto = "tcp" if proto == TCP else "udp"
    pidfile_path = os.path.realpath(
        os.path.join(
            get_p2pd_install_root(),
            f"{af}_{proto}_{serv_port}_{serv_ip}_pid.txt"
        )
    )

    try:
        import fasteners
        return fasteners.InterProcessLock(pidfile_path)
    except:
        return None
    
def avoid_time_wait(pipe):
    sock = pipe.sock
    linger = struct.pack('ii', 1, 0)
    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_LINGER,
        linger
    )

class DaemonRewrite():
    def __init__(self, conf=DAEMON_CONF):
        # Special net conf for daemon servers.
        self.conf = conf

        # AF: proto: port: ip: pipe_events.
        self.pipes = {
            IP4: {
                TCP: {}, UDP: {}
            }, 
            IP6: {
                TCP: {}, UDP: {}
            }, 
        }

    async def add_listener(self, proto, route):
        # Enforce static ports for listen port.
        assert(route.bind_port)

        # Ensure route is bound.
        assert(route.resolved)

        # Detect zombie servers.
        port, ip = route.bind_tup()[:2]
        lock = get_serv_lock(route.af, proto, port, ip)
        if lock is not None:
            if not lock.acquire(blocking=False):
                error = f"{proto}:{bind_str(route)} zombie pid"
                raise Exception(error)

        # Is the server already listening.
        is_listening = await is_serv_listening(proto, route)
        if is_listening:
            error = f"{proto}:{bind_str(route)} listen conflict."
            raise Exception(error)
        
        # Start a new server listening.
        pipe = await pipe_open(
            proto,
            route=route,
            msg_cb=self.msg_cb,
            up_cb=self.up_cb,
            conf=self.conf
        )

        # Avoid TIME_WAIT for socket.
        avoid_time_wait(pipe)

        # Store the server pipe.
        if port not in self.pipes[route.af][proto]:
            self.pipes[route.af][proto][port] = {}
        self.pipes[route.af][proto][port][ip] = pipe
        
        # Only one instance of this service allowed.
        pipe.proc_lock = lock
        return pipe

    """
    There's a special IPv6 sock option to listen on
    all address types but its not guaranteed.
    Hence I use two sockets based on supported stack.
    """
    async def listen_all(self, port, proto, nic):
        for af in nic.supported():
            route = nic.route(af)
            await route.bind(ips="*", port=port)
            await async_wrap_errors(
                self.add_listener(proto, route)
            )

    """
    Localhost here is translated to the right address
    depending on the AF supported by the NIC.
    The bind_magic function takes care of this.
    """
    async def listen_loopback(self, port, proto, nic):
        for af in nic.supported():
            route = nic.route(af)
            await route.bind(ips="localhost", port=port)
            await async_wrap_errors(
                self.add_listener(proto, route)
            )

    """
    Really no way to do this with IPv4 without adding
    something like a basic firewall. But IPv6 has the
    link-local addresses and UNL. Perhaps a basic
    firewall could be a future feature.
    """
    async def listen_local(self, port, proto, nic):
        for af in nic.supported():
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

                        # Don't modify the route table directly.
                        # Note: only binds to first IP.
                        # An IPR could represent a range.
                        local = copy.deepcopy(route)
                        ips = ipr_norm(nic_ipr)
                        await local.bind(ips=ips, port=port)
                        await async_wrap_errors(
                            self.add_listener(proto, local)
                        )

            # Supports link-locals and unique local addresses.
            if af == IP6:
                route = nic.route(af)
                for link_local in route.link_locals:
                    local = nic.route(af)
                    ips = ipr_norm(link_local)
                    await async_wrap_errors(
                        local.bind(ips=ips, port=port)
                    )
                    await async_wrap_errors(
                        self.add_listener(proto, local)
                    )

    # On message received (placeholder.)
    async def msg_cb(self, msg, client_tup, pipe):
        print("Specify your own msg_cb in a child class.")
        print(f"{msg} {client_tup}")
        await pipe.send(msg, client_tup)

    # On connection success(placeholder.)
    def up_cb(self, msg, client_tup, pipe):
        pass

    async def close(self):
        for af in VALID_AFS:
            for proto in [TCP, UDP]:
                for port in self.pipes[af][proto]:
                    for ip in self.pipes[af][proto][port]:
                        await self.pipes[af][proto][port][ip].close()



async def daemon_rewrite_workspace():
    serv = None
    try:
        nic = await Interface("wlx00c0cab5760d")
        serv = DaemonRewrite()

        await serv.listen_local(1337, TCP, nic)
        print(serv.pipes)

        while 1:
            await asyncio.sleep(1)
    except:
        await serv.close()
        log_exception()


if __name__ == "__main__":
    async_test(daemon_rewrite_workspace)
