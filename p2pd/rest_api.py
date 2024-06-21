import asyncio
from .utils import *
from .p2p_node import *
from .p2p_utils import *
from .var_names import *
from .http_server_lib import *

asyncio.set_event_loop_policy(SelectorEventPolicy())

def con_info(self, con_name, con):
    return {
        "error": 0,
        "name": con_name,
        "strategy": con.strat,
        "fd": con.sock.fileno(),
        "laddr": con.sock.getsockname(),
        "raddr": con.sock.getpeername(),
        "route": con.route.to_dict(),
        "if": {
            "name": con.route.interface.name,
            "offset": self.interfaces.index(
                con.route.interface
            )
        }
    }

def get_sub_params(v):
    # Messages are put into buckets.
    sub = SUB_ALL[:]
    if hasattr(v["name"], "msg_p"):
        sub[0] = v["name"]["msg_p"]
    if hasattr(v["name"], "addr_p"):
        sub[1] = v["name"]["addr_p"]

    timeout = 2
    if hasattr(v["name"], "timeout"):
        timeout = to_n(v["name"]["timeout"])

    return sub, timeout

class P2PDServer(RESTD):
    def __init__(self, interfaces=[], node=None):
        super().__init__()
        self.interfaces = interfaces
        self.node = node
        self.cons = {}

    @RESTD.GET(["version"])
    async def get_version(self, v, pipe):
        return {
            "title": "P2PD",
            "author": "Matthew@Roberts.PM", 
            "version": "0.1.0",
            "error": 0
        }
    
    @RESTD.GET(["ifs"])
    async def get_interfaces(self, v, pipe):
        return {
            "ifs": if_list_to_dict(self.interfaces),
            "error": 0
        }
    
    @RESTD.GET(["p2p"], ["addr"])
    async def get_peer_addr(self, v, pipe):
        return {
            "addr": to_s(self.node.addr_bytes),
            "error": 0
        }
    
    @RESTD.GET(["p2p"], ["open"])
    async def open_p2p_pipe(self, v, pipe):
        print("in matched p2p open")
        con_name = v["name"]["open"]
        dest_addr = v["pos"][0]

        # Need a unique name per con.
        if con_name in self.cons:
            print("con name already exists?")
            return {
                "msg": "Con name already exists.",
                "error": 2
            }

        # Connect to ourself for tests.
        if dest_addr == "self":
            dest_addr = self.node.addr_bytes

        print(dest_addr)

        # Attempt to make the connection.
        con, strat = await asyncio.ensure_future(
            self.node.connect(
                to_b(dest_addr),

                # All connection strats except TURN by default.
                P2P_STRATEGIES
            )
        )

        print("p2pd got con")
        print(con)
        print(strat)

        # Success -- store pipe.
        if con is not None:
            # Subscribe to any message.
            con.subscribe(SUB_ALL)

            # Remove con from table.
            def build_do_cleanup():
                def do_cleanup(msg, client_tup, pipe):
                    del self.cons[con_name]
                
                return do_cleanup

            # Add cleanup handler.
            con.add_end_cb(build_do_cleanup())

            # Return the results.
            con.strat = TXT["p2p_strat"][strat]
            self.cons[con_name] = con
            return con_info(self, con_name, con)

        # Failed to connect.
        if con is None:
            return {
                "msg": f"Con {con_name} failed connect.",
                "error": 3
            }

    @RESTD.GET(["p2p"], ["con"])
    async def get_con_info(self, v, pipe):
        con_name = v["name"]["con"]

        # Check con exists.
        con = self.cons[con_name]
        return con_info(self, con_name, con)
    
    @RESTD.GET(["p2p"], ["send"])
    async def pipe_send_text(self, v, pipe):
        con_name = v["name"]["send"]
        en_msg = urldecode(v["pos"][0])

        # Connection to send to.
        con = self.cons[con_name]

        # Send data.
        await con.send(
            data=to_b(en_msg),
            dest_tup=con.stream.dest_tup
        )

        # Return success.
        return {
            "name": con_name,
            "sent": len(en_msg),
            "error": 0
        }
    
    @RESTD.GET(["p2p"], ["recv"])
    async def pipe_recv_text(self, v, pipe):
        con_name = v["name"]["recv"]

        # Get something from recv buffer.
        con = self.cons[con_name]
        try:
            sub, timeout = get_sub_params(v)
            out = await con.recv(sub, timeout=timeout, full=True)
            if out is None:
                return {
                    "msg": f"recv buffer {sub} empty.",
                    "error": 6
                }

            return {
                "client_tup": out[0],
                "data": to_s(out[1]),
                "error": 0
            }
        except asyncio.TimeoutError:
            return {
                "msg": "recv timeout",
                "error": 5
            }

    @RESTD.GET(["p2p"], ["close"])
    async def pipe_close(self, v, pipe):
        con_name = v["name"]["close"]

        # Close the con -- fires cleanup handler.
        con = self.cons[con_name]
        await con.close()

        # Indicate closed.
        return {
            "closed": con_name,
            "error": 0
        }
    
    @RESTD.POST(["p2p"], ["binary"])
    async def pipe_send_binary(self, v, pipe):
        con_name = v["name"]["binary"]

        # Send binary data from octet-stream POST.
        con = self.cons[con_name]

        # Last content-len bytes == payload.
        await con.send(v["body"], con.stream.dest_tup)

        # Return status.
        return {
            "name": con_name,
            "sent": len(v["body"]),
            "error": 0
        }

    @RESTD.GET(["p2p"], ["binary"])
    async def pipe_get_binary(self, v, pipe):
        con_name = v["name"]["binary"]

        # Send binary data from octet-stream POST.
        con = self.cons[con_name]

        # Messages are put into buckets.
        sub, timeout = get_sub_params(v)

        # Get binary from matching buffer.
        out = await con.recv(sub, timeout=timeout, full=True)
        if out is None:
            return {
                "msg": f"recv buffer {sub} empty.",
                "error": 6
            }

        # Send it if any.
        return out

    @RESTD.GET(["p2p"], ["pipe"])
    async def http_tunnel_trick(self, v, pipe):
        con_name = v["name"]["pipe"]

        # Send binary data from octet-stream POST.
        con = self.cons[con_name]

        # Remove this server handler from con.
        # This pipe is no longer for HTTP!
        pipe.del_msg_cb(self.msg_cb)

        # Forward messages from pipe to con.
        # pipe -> con
        pipe.add_pipe(con)

        # Forward messages from con to pipe.
        # con  -> pipe
        con.add_pipe(pipe)

        # con <-----> pipe 
        return None

    @RESTD.GET(["p2p"], ["sub"])
    async def pipe_do_sub(self, v, pipe):
        con_name = v["name"]["sub"]

        # Send binary data from octet-stream POST.
        con = self.cons[con_name]

        # Messages are put into buckets.
        sub, _ = get_sub_params(v)
        con.subscribe(sub)

        # Return results.
        return {
            "name": con_name,
            "sub": f"{sub}",
            "error": 0
        }

    @RESTD.DELETE(["p2p"], ["sub"])
    async def pipe_do_unsub(self, v, pipe):
        con_name = v["name"]["sub"]
        con = self.cons[con_name]
        sub, _ = get_sub_params(v)
        con.unsubscribe(sub)

        # Return results.
        return {
            "name": con_name,
            "unsub": f"{sub}",
            "error": 0
        }

# pragma: no cover
async def start_p2pd_server(ifs=None, route=None, port=0, do_loop=True, do_init=True, enable_upnp=True):
    print("Loading interfaces...")
    print("If you've just connected a new NIC ")
    print("there can be a slight delay until it's online.")
    if enable_upnp:
        print("Doing node port forwarding and pin hole rules. Please wait.")

    # Load netifaces.
    netifaces = None
    if do_init:
        netifaces = await init_p2pd()

    # Start node server.
    ifs = ifs or await load_interfaces(netifaces=netifaces)
    print(ifs)

    #port = get_port_by_ip
    node = await start_p2p_node(
        # Attempt deterministic port allocation based on NICs.
        # If in use a random port will be used.
        port=NODE_PORT + 60 + 1,
        ifs=ifs,
        enable_upnp=enable_upnp
    )

    # Specify listen port details.
    #route = await ifs[0].route(IP4).bind(ips="127.0.0.1")

    print(route)

    # Start P2PD server.
    p2p_server = P2PDServer(ifs, node)
    await p2p_server.listen_all(
        [route],
        [port],
        [TCP]
    )

    # Stop this thread exiting.
    print(p2p_server.servers)
    bind_tup = p2p_server.servers[0][2].sock.getsockname()
    print(f"Started server on http://{bind_tup[0]}:{bind_tup[1]}")
    if do_loop:
        while 1:
            await asyncio.sleep(1)

    return p2p_server

async def p2pd_workspace():
    node = await start_p2pd_server(enable_upnp=False)

    return

    i = await Interface()
    route = await i.route().bind(ips="127.0.0.1", port=8475)
    node = await start_p2pd_server()
    server = P2PDServer2([i])
    await server.listen_all([route], [8475], [TCP])

    while 1:
        await asyncio.sleep(1)

if __name__ == "__main__":


    async_test(p2pd_workspace)