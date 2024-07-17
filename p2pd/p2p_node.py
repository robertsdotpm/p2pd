import asyncio
from .daemon import *
from .p2p_utils import *
from .node_utils import *
from .p2p_protocol import *

NODE_CONF = dict_child({
    # Reusing address can hide errors for the socket state.
    # This can make servers appear to be broken when they're not.
    "reuse_addr": False,

    "enable_upnp": False,

    "node_id": None,

    "seed": None,

    "listen_port": NODE_PORT,
    "listen_ip": None,
}, NET_CONF)

# Main class for the P2P node server.
class P2PNode(Daemon, NodeUtils):
    def __init__(self, ifs, conf=NODE_CONF):
        super().__init__()

        # Identifies this node for signal messages.
        self.node_id = conf["node_id"] or rand_plain(15)

        # Dictionary of extra configuration options.
        self.conf = conf

        # Interface list to listen on.
        self.ifs = ifs

        # Reference to various open connections.
        self.signal_pipes = {} # offset into MQTT_SERVERS
        self.pipes = {} # by [pipe_id]
        self.tcp_punch_clients = [] # by if_index
        self.turn_clients = {} # by [pipe_id]

        # Worker task processes new TCP punch requests.
        self.punch_queue = asyncio.Queue()

        # Pass signal messages to their handlers.
        self.sig_proto_handlers = SigProtoHandlers(self)

        # Maintain a list of long-running tasks.
        self.tasks = []

    # Get the P2P address of this node.
    def address(self):
        return self.addr_bytes
    
    # Set a name that can be used by others to connect to this node.
    async def nickname(self, name_field):
        pass
    
    # Connect to another node by P2P address or name.
    async def connect(self, addr_bytes, strategies=P2P_STRATEGIES):
        pass
    
    # Start the P2P node.
    async def start(self, protos=[TCP]):
        # Set machine ID for addressing.
        self.machine_id = await get_machine_id(
            "p2pd",
            self.ifs[0].netifaces
        )

        # Check at least one signal pipe was set.
        await self.load_signal_pipes()

        # Load clients for STUN requests.
        await self.load_stun_clients()

        # Start handling TCP punch requests.
        await self.start_punch_queue_worker()

        # Start the node server.
        await self.ifs_listen_all(self.conf["listen_port"], protos)

        # Translate any port 0 to actual assigned port.
        port = self.servers[0][2].sock.getsockname()[1]

        # Load P2P address bytes.
        self.addr_bytes = make_peer_addr(
            self.node_id,
            self.machine_id,
            self.ifs,
            list(self.signal_pipes),
            port=port,
            ip=self.conf["listen_ip"]
        )

        # Load P2P address as dict.
        self.p2p_addr = parse_peer_addr(self.addr_bytes)

        print(f"> P2P node = {self.addr_bytes}")
        print(self.p2p_addr)
            
        # todo: forward
        return self

    # The node server received a message.
    async def msg_cb(self, msg, client_tup, pipe):
        return await node_protocol(
            self,
            msg,
            client_tup,
            pipe
        )

    # A signal message was received from an MQTT pipe.
    async def signal_protocol(self, msg, signal_pipe):
        out = await async_wrap_errors(
            self.sig_proto_handlers.proto(msg)
        )

        if out is not None:
            await signal_pipe.send_msg(
                out,
                out.routing.dest["node_id"]
            )

if __name__ == "__main__": # pragma: no cover
    pass
    #async_test(test_p2p_node)

