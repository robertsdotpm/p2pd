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

def get_serv_lock(af, proto, serv_port):
    # Make install dir if needed.
    try:
        install_root = get_p2pd_install_root()
        pathlib.Path(install_root).mkdir(parents=True, exist_ok=True)
    except:
        log_exception()

    # Main path files.
    pidfile_path = os.path.realpath(
        os.path.join(
            get_p2pd_install_root(),
            f"{int(af)}_{int(proto)}_{serv_port}_pid.txt"
        )
    )

    try:
        import fasteners
        return fasteners.InterProcessLock(pidfile_path)
    except:
        return None

def bind_str(r):
    return f"{r.bind_tup()[0]}:{r.bind_tup()[1]}"

class DaemonRewrite():
    def __init__(self, conf=DAEMON_CONF):
        # Special net conf for daemon servers.
        self.conf = conf

        # AF: listen port: pipe_events/
        self.pipes = {
            IP4: {
                TCP: {}, UDP: {}
            }, 
            IP6: {
                TCP: {}, UDP: {}
            }, 
        }

    async def add_listener(self, proto, route, msg_cb=None, up_cb=None):
        # Enforce static ports for listen port.
        assert(route.bind_port)

        # Ensure route is bound.
        assert(route.resolved)

        # Detect zombie servers.
        lock = get_serv_lock(route.af, proto, route.bind_port)
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
        msg_cb = msg_cb or self.msg_cb
        up_cb = up_cb or self.up_cb
        pipe = await pipe_open(
            proto,
            route=route,
            msg_cb=msg_cb,
            up_cb=up_cb,
            conf=self.conf
        )

        # Store the server pipe.
        self.pipes[route.af][proto][route.bind_port] = pipe
        pipe.proc_lock = lock
        return pipe

    async def msg_cb(self, msg, client_tup, pipe):
        # Overwritten by inherited classes.
        print("This is a default proto msg_cb! Specify your own in a child class.")
        print(f"{msg} {client_tup}")
        await pipe.send(msg, client_tup)

    def up_cb(self, msg, client_tup, pipe):
        pass

    async def close(self):
        for af in VALID_AFS:
            for proto in [TCP, UDP]:
                for port in self.pipes[af][proto]:
                    await self.pipes[af][proto][port].close()

async def daemon_rewrite_workspace():
    serv = None
    try:
        nic = await Interface()
        serv = DaemonRewrite()
        route = await nic.route(IP4).bind(port=12344)
        await serv.add_listener(TCP, route)

        while 1:
            await asyncio.sleep(1)
    except:
        await serv.close()
        log_exception()


if __name__ == "__main__":
    async_test(daemon_rewrite_workspace)
