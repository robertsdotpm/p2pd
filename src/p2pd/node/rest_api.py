"""Embedded REST API server exposed by a p2pd node."""
import asyncio
from aionetiface import (
    SUB_ALL, to_b, to_s, fstr, log_exception, RESTD, create_task,
    async_wrap_errors, urldecode, if_list_to_dict, aionetiface_setup_netifaces,
    list_interfaces, load_interfaces, Interface, TCP, async_test,
    dict_child,
)
from .node import Node
from .node_defs import NODE_PORT, NODE_CONF
from ..protocol.proto_defs import P2P_STRATEGIES

REST_API_PORT = 12333


def get_opt_param(v, name):
    """Return the positional value following name in the parsed request, or None."""
    for index in range(0, len(v["pos"])):
        found_name = v["pos"][index]
        if found_name != name:
            continue

        if (index + 1) not in v["pos"]:
            break

        return v["pos"][index + 1]


def parse_addr_param(addr):
    """Parse an address parameter of the form "ip,port" (optionally wrapped in brackets/quotes).

    Returns a (ip, port) tuple on success, or the string "invalid addr tuple" on failure.
    """
    if not isinstance(addr, str):
        return "invalid addr tuple"

    # Strip surrounding whitespace and any wrapping parens/brackets.
    stripped = addr.strip()
    if stripped.startswith("(") or stripped.startswith("["):
        stripped = stripped[1:]
    if stripped.endswith(")") or stripped.endswith("]"):
        stripped = stripped[:-1]

    parts = stripped.split(",")
    if len(parts) != 2:
        return "invalid addr tuple"

    ip = parts[0].strip().strip("'").strip('"').strip()
    port_str = parts[1].strip().strip("'").strip('"').strip()

    # IP must only contain legal address characters.
    allowed = set("0123456789abcdefABCDEF.:%")
    if not ip or any(ch not in allowed for ch in ip):
        return "invalid addr tuple"

    try:
        port = int(port_str)
    except ValueError:
        return "invalid addr tuple"

    if port < 0 or port > 65535:
        return "invalid addr tuple"

    return (ip, port)


def get_sub_params(v):
    """Build a subscription filter from request params, applying msg pattern and addr overrides."""
    # Messages are put into buckets.
    sub = SUB_ALL[:]
    if "msg_p" in v["name"]:
        sub[0] = to_b(v["name"]["msg_p"])

    # Prefer split ip/port params. Fall back to legacy addr_p "ip,port" form.
    ip = get_opt_param(v, "ip")
    port = get_opt_param(v, "port")
    if ip is not None and port is not None:
        try:
            sub[1] = (str(ip).strip(), int(port))
        except (TypeError, ValueError):
            sub[1] = "invalid addr tuple"
        return sub

    addr = get_opt_param(v, "addr_p")
    if addr is not None:
        sub[1] = parse_addr_param(addr)

    return sub


def load_sub_or_default(v, subs):
    """Return the named subscription filter from subs, falling back to SUB_ALL."""
    sub_name = get_opt_param(v, "name")
    if sub_name in subs:
        return subs[sub_name]

    return SUB_ALL


class P2PDServer(RESTD):
    """HTTP REST server exposing P2PD node functionality over a local loopback interface."""

    def __init__(self, interfaces=None, node=None):
        super().__init__()
        self.interfaces = interfaces if interfaces is not None else []
        self.node = node
        self.cons = {}
        self.subs = {}

    def con_info(self, con_name, con):
        """Return a dict of connection metadata, tolerating closed/unconnected sockets."""
        # A socket might not be connected.
        try:
            raddr = con.sock.getpeername()
        except OSError:
            raddr = "not connected"

        # A socket might be closed.
        try:
            laddr = con.sock.getsockname()
        except OSError:
            laddr = "sock closed"

        # A route might end up malformed.
        try:
            con_route = con.route.to_dict()
        except (OSError, AttributeError):
            log_exception()
            con_route = "couldn't load"

        return {
            "error": 0,
            "name": con_name,
            "fd": con.sock.fileno(),
            "laddr": laddr,
            "raddr": raddr,
            "route": con_route,
            "if": {
                "name": con.route.interface.name,
                "offset": self.interfaces.index(con.route.interface),
            },
        }

    @RESTD.GET(["version"])
    async def get_version(self, v, pipe):
        """Return the P2PD version and author information."""
        return {
            "title": "P2PD",
            "author": "Matthew@Roberts.PM",
            "version": "3.0.0",
            "error": 0,
        }

    @RESTD.GET(["ifs"])
    async def get_interfaces(self, v, pipe):
        """Return a JSON-serialised list of all loaded network interfaces."""
        try:
            return {"ifs": if_list_to_dict(self.interfaces), "error": 0}
        except (ValueError, AttributeError):
            log_exception()
            return {"error": 4, "msg": "unable to convert ifs to dict."}

    @RESTD.GET(["addr"])
    async def get_peer_addr(self, v, pipe):
        """Return the serialised P2P address bytes of this node."""
        if self.node.addr_bytes is None:
            return {"error": 5, "msg": "p2pd node addr bytes is none."}
        return {"addr": to_s(self.node.addr_bytes), "error": 0}

    @RESTD.GET(["open"])
    async def open_p2p_pipe(self, v, pipe):
        """Initiate a P2P connection to dest_addr and store it under the given con_name."""
        con_name = v["name"]["open"]
        dest_addr = v["pos"][0]

        # Need a unique name per con.
        if con_name in self.cons:
            return {"msg": "Con name already exists.", "error": 2}

        # Connect to ourself for tests.
        if dest_addr == "self":
            if self.node.addr_bytes is None:
                return {"error": 5, "msg": "p2pd node addr bytes is none."}

            dest_addr = self.node.addr_bytes

        # Attempt to make the connection.
        con = await create_task(
            async_wrap_errors(
                self.node.connect(
                    to_b(dest_addr),
                    # All connection strats except TURN by default.
                    P2P_STRATEGIES,
                )
            )
        )

        # Success -- store pipe.
        if con is not None:
            # Subscribe to any message.
            con.subscribe(SUB_ALL)

            # Remove con from table.
            def build_do_cleanup():
                """Return a closure that removes con_name from the connections table."""
                def do_cleanup(msg, client_tup, pipe):
                    """Remove the connection from the table when the pipe ends."""
                    del self.cons[con_name]

                return do_cleanup

            # Add cleanup handler.
            con.add_end_cb(build_do_cleanup())

            # Return the results.
            self.cons[con_name] = con
            return self.con_info(con_name, con)

        # Failed to connect.
        if con is None:
            return {"msg": fstr("Con {0} failed connect.", (con_name,)), "error": 3}

    @RESTD.GET(["info"])
    async def get_con_info(self, v, pipe):
        """Return socket and route metadata for the named open connection."""
        con_name = v["name"]["con"]
        if con_name not in self.cons:
            return {"error": 7, "msg": fstr("con {0} does not exist", (con_name,))}

        # Check con exists.
        con = self.cons[con_name]
        return self.con_info(con_name, con)

    @RESTD.GET(["send"])
    async def pipe_send_text(self, v, pipe):
        """URL-decode the message parameter and send it as text over the named connection."""
        con_name = v["name"]["send"]
        en_msg = urldecode(v["pos"][0])

        # Connection to send to.
        con = self.cons[con_name]

        # Send data.
        send_success = await con.send(data=to_b(en_msg), dest_tup=con.stream.dest_tup)

        # Check return value.
        if not send_success:
            return {"error": 8, "msg": "send txt failed"}

        # Return success.
        return {"con_name": con_name, "sent": len(en_msg), "error": 0}

    @RESTD.GET(["recv"])
    async def pipe_recv_text(self, v, pipe):
        """Wait for and return a text message from the named connection's receive buffer."""
        con_name = v["name"]["recv"]

        # Get something from recv buffer.
        con = self.cons[con_name]
        sub = load_sub_or_default(v, self.subs)
        timeout = get_opt_param(v, "timeout") or 2
        try:
            out = await con.recv(sub, timeout=timeout, full=True)
            if out is None:
                return {"msg": fstr("recv buffer {0} empty.", (sub,)), "error": 6}

            return {
                "con_name": con_name,
                "client_tup": out[0],
                "data": to_s(out[1]),
                "error": 0,
            }
        except asyncio.TimeoutError:
            return {"msg": "recv timeout", "error": 5}

    @RESTD.GET(["close"])
    async def pipe_close(self, v, pipe):
        """Close the named P2P connection and remove it from the connection table."""
        con_name = v["name"]["close"]

        # Close the con -- fires cleanup handler.
        con = self.cons[con_name]
        await con.close()

        # Indicate closed.
        return {"closed": con_name, "error": 0}

    @RESTD.POST(["binary"])
    async def pipe_send_binary(self, v, pipe):
        """Send the raw POST body as binary data over the named P2P connection."""
        con_name = v["name"]["binary"]

        # Send binary data from octet-stream POST.
        con = self.cons[con_name]

        # Last content-len bytes == payload.
        send_success = await con.send(v["body"], con.stream.dest_tup)
        if not send_success:
            return {"error": 8, "msg": "binary send failed."}

        # Return status.
        return {"con_name": con_name, "sent": len(v["body"]), "error": 0}

    @RESTD.GET(["binary"])
    async def pipe_get_binary(self, v, pipe):
        """Read raw binary data from the named connection's receive buffer and return it directly."""
        con_name = v["name"]["binary"]

        # Send binary data from octet-stream POST.
        con = self.cons[con_name]

        # Messages are put into buckets.
        sub = load_sub_or_default(v, self.subs)

        # Get binary from matching buffer.
        timeout = get_opt_param(v, "timeout") or 2
        out = await con.recv(sub, timeout=timeout, full=True)
        if out is None:
            return {"msg": fstr("recv buffer {0} empty.", (sub,)), "error": 6}

        # Send it if any.
        return out[1]

    @RESTD.GET(["tunnel"])
    async def http_tunnel_trick(self, v, pipe):
        """Upgrade this HTTP connection to a transparent bidirectional tunnel to the named P2P pipe."""
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

    @RESTD.GET(["sub"], ["name"], ["msg_p"])
    async def pipe_do_sub(self, v, pipe):
        """Create a named message subscription filter on the specified P2P connection."""
        # Get variable names.
        con_name = v["name"]["sub"]
        sub_name = v["name"]["name"]
        if sub_name == "all":
            return {"msg": "reserved sub name", "error": 10}

        # Make sure sub is new.
        if sub_name in self.subs:
            return {
                "msg": "sub name already exists.",
                "error": 9,
            }

        # Connection ref.
        con = self.cons[con_name]

        # Messages are put into buckets.
        sub = get_sub_params(v)
        self.subs[sub_name] = sub
        con.subscribe(sub)

        # Return results.
        return {
            "con_name": con_name,
            "sub_name": sub_name,
            "sub": fstr("{0}", (sub,)),
            "error": 0,
        }

    @RESTD.DELETE(["sub"], ["name"])
    async def pipe_do_unsub(self, v, pipe):
        """Remove a named subscription filter from the specified P2P connection."""
        con_name = v["name"]["sub"]
        sub_name = v["name"]["name"]
        con = self.cons[con_name]
        if sub_name == "all":
            sub = SUB_ALL
            con.unsubscribe(SUB_ALL)
        else:
            sub = self.subs[sub_name]
            con.unsubscribe(sub)
            del self.subs[sub_name]

        # Return results.
        return {"con_name": con_name, "unsub": fstr("{0}", (sub,)), "error": 0}


# pragma: no cover
async def start_p2pd_server(port=REST_API_PORT, ifs=None, enable_upnp=False):
    """Start a P2PD node and bind the REST API server to the loopback interface on port."""
    print("Loading interfaces...")
    print("If you've just connected a new NIC ")
    print("there can be a slight delay until it's online.")
    if enable_upnp:
        print("Doing node port forwarding and pin hole rules.")

    # Passed to setup the p2p node.
    node_conf = dict_child({"enable_upnp": enable_upnp}, NODE_CONF)

    # Load netifaces.
    netifaces = await aionetiface_setup_netifaces()

    # Load interfaces.
    if ifs is None:
        ifs = []
    if not ifs:
        # Load a list of interface names.
        if_names = await list_interfaces(netifaces=netifaces)
        if not if_names:
            raise AssertionError("p2pd rest could not find if names")

        # Load those interfaces with NAT details.
        ifs = await load_interfaces(if_names, Interface)
        if not ifs:
            raise AssertionError("p2pd rest no ifs loaded.")

    # Start P2PD node.
    node = Node(ifs, port=NODE_PORT + 60 + 1, conf=node_conf)
    await node.start()

    # Start P2PD server.
    p2p_server = P2PDServer(ifs, node)
    for nic in ifs:
        await p2p_server.listen_loopback(TCP, port, nic)

    # Stop this thread exiting.
    return p2p_server


async def p2pd_workspace():
    """Launch the P2PD REST server and block indefinitely for manual testing."""
    await start_p2pd_server()
    print(fstr("http://localhost:{0}/", (REST_API_PORT,)))
    while True:
        await asyncio.sleep(1)


if __name__ == "__main__":
    async_test(p2pd_workspace)
