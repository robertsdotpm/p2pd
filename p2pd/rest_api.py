import asyncio
import re
import urllib
from .p2p_node import *
from .var_names import *
from .http_lib import *

P2PD_PORT = 12333
P2PD_CORS = ['null', 'http://127.0.0.1']

asyncio.set_event_loop_policy(SelectorEventPolicy())

# Support passing in GET params using path seperators.
# Ex: /timeout/10/sub/all -> {'timeout': '10', 'sub': 'all'}
def get_params(field_names, url_path):
    # Return empty.
    if field_names == []:
        return {}

    # Build regex match string.
    p = ""
    for field in field_names:
        # Escape any regex-specific characters.
        as_literal = re.escape(field)
        as_literal = as_literal.replace("/", "")

        # (/ field name / non dir chars )
        # All are marked as optional.
        p += f"(?:/({as_literal})/([^/]+))|"

    # Repeat to match optional instances of the params.
    p = f"(?:{p[:-1]})+"

    # Convert the marked pairs to a dict.
    params = {}
    safe_url = re.escape(url_path)
    results = re.findall(p, safe_url)
    if len(results):
        results = results[0]
        for i in range(0, int(len(results) / 2)):
            # Every 2 fields is a named value.
            name = results[i * 2]
            value = results[(i * 2) + 1]
            value = re.unescape(value)

            # Param not set.
            if name == "":
                continue

            # Save by name.
            name = re.unescape(name)
            params[name] = value

    # Return it for use.
    return params

def api_closure(url_path):
    # Fields list names a p result and is in a fixed order.
    # Get names matches named values and is in a variable order.
    def api(p, field_names=[], get_names=[]): 
        out = re.findall(p, url_path)
        as_dict = {}
        if len(out):
            if isinstance(out[0], tuple):
                out = out[0]

            if len(field_names):
                for i in range(  min( len(out), len(field_names) )  ):
                    as_dict[field_names[i]] = out[i]
            else:
                as_dict["out"] = out
            

        params = get_params(get_names, url_path)
        if len(params) and len(as_dict):
            return dict_merge(params, as_dict)
        else:
            return as_dict

    return api

# p = {}, optional = [ named ... ]
# default = [ matching values ... ]
def set_defaults(p, optional, default):
    # Set default param values.
    for i, named in enumerate(optional):
        if named not in p:
            p[named] = default[i]

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
        # Parse http request.
        try:
            req = ParseHTTPRequest(msg)
        except Exception:
            log_exception()
            return

        # Deny restricted origins.
        if req.hdrs["Origin"] not in P2PD_CORS:
            resp = {
                "msg": "Invalid origin.",
                "error": 5
            }
            await send_json(resp, req, client_tup, pipe)
            return

        # Implements 'pre-flight request checks.'
        cond_1 = "Access-Control-Request-Method" in req.hdrs
        cond_2 = "Access-Control-Request-Headers" in req.hdrs
        if cond_1 and cond_2:
            # CORS policy header line.
            allow_origin = "Access-Control-Allow-Origin: %s" % (
                req.hdrs["Origin"]
            )

            # HTTP response.
            out  = b"HTTP/1.1 200 OK\r\n"
            out += b"Content-Length: 0\r\n"
            out += b"Connection: keep-alive\r\n"
            out += b"Access-Control-Allow-Methods: POST, GET, DELETE\r\n"
            out += b"Access-Control-Allow-Headers: *\r\n"
            out += b"%s\r\n\r\n" % (to_b(allow_origin))
            await pipe.send(out, client_tup)
            return

        # Critical URL path part is encoded.
        url_parts = urllib.parse.urlparse(req.path)
        url_path = urllib.parse.unquote(url_parts.path)

        # Luckily URL decodes.
        url_query = urllib.parse.parse_qs(url_parts.query)
        api = api_closure(url_path)

        # Output JSON response for the API.
        async def get_response():
            # Show version information.
            if api("/version"):
                return {
                    "title": "P2PD",
                    "author": "Matthew@Roberts.PM", 
                    "version": "0.1.0",
                    "error": 0
                }

            # All interface details.
            if api("(/ifs)"):
                return {
                    "ifs": if_list_to_dict(self.interfaces),
                    "error": 0
                }

            # Node's own 'p2p address.'
            if api("/p2p/addr"):
                return {
                    "addr": to_s(self.node.addr_bytes),
                    "error": 0
                }

            # Create a new connection and name it.
            named = ["con_name", "dest_addr"]
            p = api("/p2p/open/([^/]*)/([^/]*)", named)
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
            p = api("/p2p/con/([^/]*)", ["con_name"])
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
            p = api("/p2p/sub/([^/]*)", named, params)
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
            p = api("/p2p/send/([^/]*)/([\s\S]+)", named)
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
            p = api("/p2p/recv/([^/]*)", named, optional)
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
            p = api("/p2p/pipe/([^/]*)", named)
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
            p = api("/p2p/binary/([^/]*)", named, optional)
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
            p = api("/p2p/close/([^/]*)", named)
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

# pragma: no cover
async def start_p2pd_server(ifs=None, route=None, port=0, do_loop=True, do_init=True):
    print("Loading interfaces...")
    print("If you've just connected a new NIC ")
    print("there can be a slight delay until it's online.")

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
        enable_upnp=True
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