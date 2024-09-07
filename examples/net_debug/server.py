from p2pd import *

class NetDebugServer(Daemon):
    async def msg_cb(self, msg, client_tup, pipe):
        # Parse HTTP message and handle CORS.
        req = await rest_service(msg, client_tup, pipe)

        # Output JSON response for the API.
        async def get_response():
            # Send 'hello' to a remote client to test it.
            named = ["proto", "dest_addr", "dest_port", "route_ip", "src_port"]
            ip_p = "[0-9a-fA-F:.]"
            p = req.api(f"/hello/((?:udp)|(?:tcp))/([^/]+)/([0-9]+)/({ip_p}+)/([0-9]+)", named)
            if p:
                # Get port and check it's valid.
                dest_port = to_n(p["dest_port"])
                if not valid_port(dest_port):
                    return {
                        "error": 1,
                        "msg": "invalid port for /hello"
                    }

                # Check src port.
                src_port = to_n(p["src_port"])
                if src_port != 0:
                    if not valid_port(src_port):
                        return {
                            "error": 6,
                            "msg": "invalid src port for /hello"
                        }

                # Error thrown and logged in handler if not valid.
                route_ipr = IPRange(p["route_ip"])
                af = route_ipr.af
                route = await self.rp[af].locate(route_ipr).bind(port=src_port)
                if route is None:
                    return {
                        "error": 3,
                        "msg": "this server doesn't control that IP."
                    }

                # Make pipe used to send hello message.
                proto = PROTO_LOOKUP[p["proto"].upper()]
                dest_addr = (p["dest_addr"], dest_port)
                hello_pipe = await pipe_open(proto, dest_addr, route)
                hello_from = hello_pipe.sock.getsockname()

                # Send hello and close the pipe.
                await hello_pipe.send(b"hello")
                await hello_pipe.close()

                return {
                    "error": 0,
                    "msg": f"sent hello to {p['proto']}:{dest_addr.tup} from {hello_from} route = {route}"
                }

            # Make a TCP connection back to a service to test port forwarding.
            named = ["port"]
            p = req.api(f"/reverse/([0-9]+)", named)
            if p:
                # Get port and check it's valid.
                dest_port = to_n(p["port"])
                if not valid_port(dest_port):
                    return {
                        "error": 4,
                        "msg": "invalid port for /reverse"
                    }

                # Peers address of this connection.
                dest_tup = (pipe.sock.getpeername()[0], dest_port)                
                try:
                    # Resolve dest tuple to address.
                    dest_addr = dest_tup

                    # Attempt to make TCP con to dest_port.
                    route = copy.deepcopy(pipe.route)
                    tcp_pipe = await pipe_open(
                        route=await route.bind(),
                        proto=TCP,
                        dest=dest_addr,
                        conf=dict_child({
                            "con_timeout": 1
                        }, NET_CONF) 
                    )

                    # Failure.
                    if tcp_pipe is None:
                        raise Exception("Failed to connect.")

                    # Success if no exception fired.
                    await tcp_pipe.close()
                    return {
                        "error": 0,
                        "msg": f"tcp service {dest_tup} is reachable."
                    }
                except Exception:
                    return {
                        "error": 5,
                        "msg": f"tcp service {dest_tup} is not reachable."
                    }

            # Show information of the connection to the peer.
            p = req.api("/mapping")
            if p:
                sock = pipe.sock
                return {
                    "error": 0,
                    "fd": sock.fileno(),
                    "laddr": sock.getsockname(),
                    "raddr": sock.getpeername(),
                    "route": pipe.route.to_dict(),
                    "if": {
                        "name": pipe.route.interface.name
                    }
                }

            # Fallback and serve all other purposes.
            return {
                "error": 2,
                "msg": "method not implemented"
            }

        # Return JSON response to browser.
        resp = await get_response()
        if resp is not None:
            await send_json(
                resp,
                req,
                client_tup,
                pipe
            )

async def start_net_debug():
    i = await Interface().start()
    net_debug_server = NetDebugServer()
    net_debug_server.set_rp(i.rp)
    await net_debug_server.listen_all(
        [i.rp[IP4], i.rp[IP6]],
        [20000],
        [TCP, UDP]
    )

    while 1:
        await asyncio.sleep(10)

async_test(start_net_debug)