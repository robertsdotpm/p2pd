
import asyncio
from .daemon import *
from .p2p_addr import *
from .p2p_utils import *
from .p2p_node_extra import *

NODE_CONF = dict_child({
    """
    Note:
    Reusing address can hide socket errors and
    make servers appear broken when they're not.

    Todo: write code to test this state against
    the node server.
    """
    "reuse_addr": False,
    "node_id": None,
    "listen_ip": None,
    "seed": None,
    "enable_upnp": False,
    "sig_pipe_no": SIGNAL_PIPE_NO,
}, NET_CONF)

# Main class for the P2P node server.
class P2PNode(Daemon, P2PNodeExtra):
    def __init__(self, ifs, port=NODE_PORT, conf=NODE_CONF):
        super().__init__()
        
        # Main variables for the class.
        self.conf = conf
        self.node_id = conf["node_id"] or rand_plain(15)
        self.listen_port = port
        self.ifs = ifs

        # Handlers for the node protocol.
        self.msg_cbs = []

        # Main pipe connections.
        self.pipes = {} # by pipe_id
        self.tcp_punch_clients = {} # by if_index
        self.turn_clients = {} # by pipe_id
        self.signal_pipes = {} # by MQTT_SERVERS index

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

        
        if isinstance(out, SigMsg):
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

        # Used by TCP punch clients.
        await self.load_stun_clients()

        # MQTT server offsets for signal protocol.
        if self.conf["sig_pipe_no"]:
            await self.load_signal_pipes()
        #self.signal_pipes[0] = None

        # Accept TCP punch requests.
        self.start_punch_worker()

        """
        # Check at least one signal pipe was set.
        if not len(self.signal_pipes):
            raise Exception("Unable to get any signal pipes.")
        """

        # Start the server for the node protocol.
        await self.listen_on_ifs()

        # Translate any port 0 to actual assigned port.
        node_sock = self.servers[0][2].sock
        listen_port = node_sock.getsockname()[1]
        print(f"Server port = {listen_port}")
        print(self.ifs)

        # Build P2P address bytes.
        self.addr_bytes = make_peer_addr(
            self.node_id,
            self.machine_id,
            self.ifs,
            list(self.signal_pipes),
            port=listen_port,
            ip=self.conf["listen_ip"]
        )

        # Save a dict version of the address fields.
        self.p2p_addr = parse_peer_addr(self.addr_bytes)
        print(f"> P2P node = {self.addr_bytes}")
        return self
    
    # Connect to a remote P2P node using a number of techniques.
    async def connect(self, addr_bytes, strategies=P2P_STRATEGIES, timeout=60):
        pass

    # Get our node server's address.
    def address(self):
        return self.addr_bytes
    
    async def register(self, name_field):
        pass

