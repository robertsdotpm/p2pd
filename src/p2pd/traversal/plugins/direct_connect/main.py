import asyncio
from ....utility.utils import *
from ....net.net_utils import *
from ....net.address import Address
from ....net.pipe.pipe_open import pipe_open
from ....net.pipe.pipe import *
from ....node.node_defs import *

async def direct_connect(tunnel, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
    # Connect to this address.
    dest = (
        str(dest_info["ip"]),
        dest_info["port"],
    )

    # (1) Get first interface for AF.
    # (2) Build a 'route' from it with it's main NIC IP.
    # (3) Bind to the route at port 0. Return itself.
    if af == IP4:
        route = await iface.route(af).bind()
    if af == IP6:
        if "fe80" == dest[0][:4]:
            route = iface.route(af)
            await route.bind(
                ips=str(route.link_locals[0])
            )
        else:
            route = await iface.route(af).bind()

    # Connect to destination.
    try:
        pipe = await Pipe(TCP, dest, route).connect(tunnel.node.msg_cb)
    except:
        log_exception()
        pipe = None

    if pipe is None:
        return
    
    if pipe.sock is None:
        return

    await pipe.send(CON_ID_MSG + to_b(fstr(" {0}\n", (pipe_id,))))
    tunnel.node.pipe_ready(pipe_id, pipe)
    return pipe