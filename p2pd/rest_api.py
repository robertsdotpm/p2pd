import asyncio
from .p2p_node import *
from .p2p_utils import *
from .var_names import *
from .http_server_lib import *

asyncio.set_event_loop_policy(SelectorEventPolicy())

def con_info(self, p, con):
    return {
        "error": 0,
        "name": p["con_name"],
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

class P2PDServer(Daemon):
    def __init__(self, if_list, node):
        super().__init__(if_list)
        self.node = node
        self.cons = {}

    async def msg_cb(self, msg, client_tup, pipe):
        # Parse HTTP message and handle CORS.
        req = await rest_service(msg, client_tup, pipe)

        # Output JSON response for the API.
        async def get_response():
            # Show version information.
            if req.api("/version"):
                return {
                    "title": "P2PD",
                    "author": "Matthew@Roberts.PM", 
                    "version": "0.1.0",
                    "error": 0
                }

            # All interface details.
            if req.api("(/ifs)"):
                return {
                    "ifs": if_list_to_dict(self.interfaces),
                    "error": 0
                }

            # Node's own 'p2p address.'
            if req.api("/p2p/addr"):
                return {
                    "addr": to_s(self.node.addr_bytes),
                    "error": 0
                }

            # Create a new connection and name it.
            named = ["con_name", "dest_addr"]
            p = req.api("/p2p/open/([^/]*)/([^/]*)", named)
            if p:
                # Need a unique name per con.
                if p["con_name"] in self.cons:
                    return {
                        "msg": "Con name already exists.",
                        "error": 2
                    }

                # Connect to ourself for tests.
                if p["dest_addr"] == "self":
                    p["dest_addr"] = self.node.addr_bytes

                # Attempt to make the connection.
                con, strat = await self.node.connect(
                    to_b(p["dest_addr"]),

                    # All connection strats except TURN by default.
                    P2P_STRATEGIES
                )

                # Success -- store pipe.
                if con is not None:
                    # Subscribe to any message.
                    con.subscribe(SUB_ALL)

                    # Remove con from table.
                    def build_do_cleanup():
                        def do_cleanup(msg, client_tup, pipe):
                            del self.cons[ p["con_name"] ]
                        
                        return do_cleanup

                    # Add cleanup handler.
                    con.add_end_cb(build_do_cleanup())

                    # Return the results.
                    con.strat = TXT["p2p_strat"][strat]
                    self.cons[ p["con_name"] ] = con
                    return con_info(self, p, con)

                # Failed to connect.
                if con is None:
                    return {
                        "msg": f"Con {p['con_name']} failed connect.",
                        "error": 3
                    }

            # Return con info.
            p = req.api("/p2p/con/([^/]*)", ["con_name"])
            if p:
                # Check con exists.
                if p["con_name"] not in self.cons:
                    return {
                        "msg": f"Con name {p['con_name']} not found.",
                        "error": 4,
                    }

                con = self.cons[ p["con_name"] ]
                return con_info(self, p, con)

            # Subscribe to certain message patterns.
            named = ["con_name"]
            params = ["msg_p", "addr_p"]
            defaults = [b"", b""]
            p = req.api("/p2p/sub/([^/]*)", named, params)
            if p:
                # Check con exists.
                if p["con_name"] not in self.cons:
                    return {
                        "msg": f"Con name {p['con_name']} not found.",
                        "error": 4,
                    }

                # Set default values for $_GET.
                set_defaults(p, params, defaults)
                sub = [ to_b(p["msg_p"]), to_b(p["addr_p"]) ]
                con = self.cons[ p["con_name" ] ]

                # Subscribe.
                if req.command == "GET":
                    con.subscribe(sub)

                    # Return results.
                    return {
                        "name": p["con_name"],
                        "sub": f"{sub}",
                        "error": 0
                    }

                # Unsubscribe.
                if req.command == "DELETE":
                    con.unsubscribe(sub)

                    # Return results.
                    return {
                        "name": p["con_name"],
                        "unsub": f"{sub}",
                        "error": 0
                    }
            
            # Send a text-based message to a named con.
            named = ["con_name", "txt"]
            p = req.api("/p2p/send/([^/]*)/([\s\S]+)", named)
            if p:
                # Check con exists.
                if p["con_name"] not in self.cons:
                    return {
                        "msg": f"Con name {p['con_name']} not found.",
                        "error": 4,
                    }

                # Connection to send to.
                con = self.cons[ p["con_name"] ]

                # Send data.
                await con.send(
                    data=to_b(p["txt"]),
                    dest_tup=con.stream.dest_tup
                )

                # Return success.
                return {
                    "name": p["con_name"],
                    "sent": len(p["txt"]),
                    "error": 0
                }

            # Send a text-based message to a named con.
            optional = ["timeout", "msg_p", "addr_p"]
            defaults = [0, b"", b""]
            named = ["con_name"]
            p = req.api("/p2p/recv/([^/]*)", named, optional)
            if p:
                # Check con exists.
                if p["con_name"] not in self.cons:
                    return {
                        "msg": f"Con name {p['con_name']} not found.",
                        "error": 4,
                    }

                # Set default values for $_GET.
                set_defaults(p, optional, defaults)

                # Get something from recv buffer.
                con = self.cons[ p["con_name"] ]
                try:
                    sub = [ to_b(p["msg_p"]), to_b(p["addr_p"]) ]
                    timeout = to_n(p["timeout"])
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

            # Chain together connections -- fully async.
            p = req.api("/p2p/pipe/([^/]*)", named)
            if p:
                # Check con exists.
                if p["con_name"] not in self.cons:
                    await pipe.close()
                    return None

                con = self.cons[ p["con_name"] ]

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

            # Binary send / recv methods.
            p = req.api("/p2p/binary/([^/]*)", named, optional)
            if p:
                # Check con exists.
                if p["con_name"] not in self.cons:
                    return {
                        "msg": f"Con name {p['con_name']} not found.",
                        "error": 4,
                    }

                # Send binary data from octet-stream POST.
                con = self.cons[ p["con_name"] ]
                if req.command == "POST":
                    # Content len header must exist.
                    if "Content-Length" not in req.hdrs:
                        return {
                            "msg": "content len header in binary POST",
                            "error": 6
                        }

                    # Content len must not exceed msg len.
                    payload_len = to_n(req.hdrs["Content-Length"])
                    if not in_range(payload_len, [1, len(msg)]):
                        return {
                            "msg": "invalid content len for bin POST",
                            "error": 7
                        }

                    # Last content-len bytes == payload.
                    data = msg[-payload_len:]
                    await con.send(data, con.stream.dest_tup)

                    # Return status.
                    return {
                        "name": p["con_name"],
                        "sent": payload_len,
                        "error": 0
                    }

                # Get buffer and send as binary stream.
                if req.command == "GET":
                    set_defaults(p, optional, defaults)
                    timeout = to_n(p["timeout"])
                    sub = [ p["msg_p"], p["addr_p"] ]

                    # Get binary from matching buffer.
                    out = await con.recv(sub, timeout=timeout, full=True)
                    if out is None:
                        return {
                            "msg": f"recv buffer {sub} empty.",
                            "error": 6
                        }

                    # Send it if any.
                    if out is not None:
                        await send_binary(out, req, client_tup, pipe)
                        return None

            # Close a connection.
            p = req.api("/p2p/close/([^/]*)", named)
            if p:
                # Check con exists.
                if p["con_name"] not in self.cons:
                    return {
                        "msg": f"Con name {p['con_name']} not found.",
                        "error": 4,
                    }

                # Close the con -- fires cleanup handler.
                con = self.cons[ p["con_name"] ]
                await con.close()

                # Indicate closed.
                return {
                    "closed": p["con_name"],
                    "error": 0
                }

            return {
                "msg": "No API method found.",
                "error": 1
            }

        resp = await get_response()
        if resp is not None:
            await send_json(
                resp,
                req,
                client_tup,
                pipe
            )

    async def close(self):
        await self.node.close()
        await super().close()

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
    #port = get_port_by_ip
    node = await start_p2p_node(
        # Attempt deterministic port allocation based on NICs.
        # If in use a random port will be used.
        port=-1,
        ifs=ifs,
        enable_upnp=enable_upnp
    )

    # Start P2PD server.
    route = route or await ifs[0].route().bind(ips="127.0.0.1")
    p2p_server = P2PDServer(ifs, node)
    await p2p_server.listen_all(
        [route],
        [port],
        [TCP]
    )

    # Stop this thread exiting.
    bind_tup = p2p_server.servers[0][2].sock.getsockname()
    print(f"Started server on http://{bind_tup[0]}:{bind_tup[1]}")
    if do_loop:
        while 1:
            await asyncio.sleep(1)

    return p2p_server

if __name__ == "__main__":
    async_test(start_p2pd_server)