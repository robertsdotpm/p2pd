
import asyncio
from .daemon import *
from .p2p_addr import *
from .p2p_utils import *
from .p2p_node_extra import *

NODE_CONF = dict_child({
    # Reusing address can hide errors for the socket state.
    # This can make servers appear to be broken when they're not.
    "reuse_addr": False,
    "node_id": None,
    "listen_ip": None,
    "seed": None,
    "enable_upnp": False,
}, NET_CONF)

# Main class for the P2P node server.
class P2PNode(Daemon, P2PUtils):
    def __init__(self, ifs, port=NODE_PORT, conf=NODE_CONF):
        super().__init__()
        
        # Main variables for the class.
        self.conf = conf
        self.node_id = conf["node_id"] or rand_plain(15)
        self.port = port
        self.ifs = ifs

        # Handlers for the node's custom protocol functions.
        self.msg_cbs = []

        # Main pipe connections.
        self.signal_pipes = {} # offsets into MQTT_SERVERS
        self.pipes = {} # by [pipe_id]
        self.tcp_punch_clients = {} # by if_index
        self.turn_clients = {}

        # Pending TCP punch queue.
        self.punch_queue = asyncio.Queue()

        # Signal protocol class instance.
        self.sig_proto_handlers = SigProtoHandlers(self)

        # Fixed reference for long-running tasks.
        self.tasks = []

    # Used by the node servers.
    async def msg_cb(self, msg, client_tup, pipe):
        return await node_protocol(self, msg, client_tup, pipe)
    
    # Used by the MQTT clients.
    async def signal_protocol(self, msg, signal_pipe):
        out = await async_wrap_errors(
            self.sig_proto_handlers.proto(msg)
        )

        if out is not None:
            await signal_pipe.send_msg(
                out,
                out.routing.dest["node_id"]
            )

    async def dev(self, protos=[TCP]):
        # Set machine id.
        self.machine_id = await self.load_machine_id(
            "p2pd",
            self.ifs[0].netifaces
        )

        # MQTT server offsets to try.
        await self.load_signal_pipes()

        # Check at least one signal pipe was set.
        if not len(self.signal_pipes):
            raise Exception("Unable to get any signal pipes.")

        await self.listen_on_ifs()

        # Translate any port 0 to actual assigned port.
        # First server, field 3 == base_proto.
        # sock = listen sock, getsocketname = (bind_ip, bind_port, ...)
        port = self.servers[0][2].sock.getsockname()[1]
        print(f"Server port = {port}")

        self.addr_bytes = make_peer_addr(self.node_id, self.machine_id, self.ifs, list(self.signal_pipes), port=port, ip=self.conf["listen_ip"])
        self.p2p_addr = parse_peer_addr(self.addr_bytes)
        print(f"> P2P node = {self.addr_bytes}")
        print(self.p2p_addr)

        # TODO: placeholder.
        await self.load_stun_clients()
            
        return self


    # Connect to a remote P2P node using a number of techniques.
    async def connect(self, addr_bytes, strategies=P2P_STRATEGIES, timeout=60):
        pass

    # Get our node server's address.
    def address(self):
        return self.addr_bytes
    
    """
    Register this name on up to N IRC servers if needed.
    Then set the value at that name to this nodes address
    """
    async def register(self, name_field):
        pass



