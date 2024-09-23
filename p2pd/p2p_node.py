
import asyncio
from .interface import load_interfaces
from .daemon import *
from .daemon import *
from .p2p_addr import *
from .p2p_utils import *
from .p2p_node_extra import *
from .nickname import *

NODE_CONF = dict_child({
    """
    Note:
    Reusing address can hide socket errors and
    make servers appear broken when they're not.

    Todo: write code to test this state against
    the node server.
    """
    "reuse_addr": False,
    "listen_ip": None,
    "enable_upnp": False,
    "sig_pipe_no": SIGNAL_PIPE_NO,
}, NET_CONF)

# Main class for the P2P node server.
class P2PNode(P2PNodeExtra, Daemon):
    def __init__(self, ifs=[], port=NODE_PORT, conf=NODE_CONF):
        super().__init__()
        self.__name__ = "P2PNode"
        assert(port)
        
        # Main variables for the class.
        self.conf = conf
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
        self.punch_worker_task = None
        self.active_punchers = 0
        self.max_punchers = 0

        # Signal protocol class instance.
        self.sig_proto_handlers = SigProtoHandlers(self)
        self.sig_msg_queue = asyncio.Queue()
        self.sig_msg_dispatcher_task = None

        # Fixed reference for long-running tasks.
        self.tasks = []

        # Cryptography for authenticated messages.
        self.sk = self.load_signing_key()
        self.vk = self.sk.verifying_key
        self.node_id = hashlib.sha256(
            self.vk.to_string("compressed")
        ).hexdigest()[:25]

        # Table of authenticated users.
        self.auth = {
            self.node_id: {
                "sk": self.sk,
                "vk": self.vk.to_string("compressed"),
            }
        }

        # Watch for idle connections.
        self.last_recv_table = {} # [pipe] -> time
        self.last_recv_queue = [] # FIFO pipe ref

        # Set on start.
        self.addr_bytes = None

    async def add_msg_cb(self, msg_cb):
        self.msg_cbs.append(msg_cb)

    # Used by the node servers.
    async def msg_cb(self, msg, client_tup, pipe):
        """
        TCP is stream-orientated and may buffer small sends.
        New lines end messages. So multiple messages can
        be read by splitting at a new line. Excluding
        complex cases of partial replies (who cares for now.)
        """

        # Recv a message for a pipe being monitored for idleness.
        if pipe in self.last_recv_table:
            self.last_recv_table[pipe] = time.time()

        print(f"Node msg cb = {msg}")
        for sub_msg in msg.split(b'\n'):
            if not len(sub_msg): continue
            await node_protocol(self, sub_msg, client_tup, pipe)
            for msg_cb in self.msg_cbs:
                run_handler(pipe, msg_cb, client_tup, sub_msg)
    
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

    async def start(self, sys_clock=None):
        # Load ifs.
        t = time.time()
        if not len(self.ifs):
            try:
                if_names = await list_interfaces()
                self.ifs = await load_interfaces(if_names)
            except:
                log_exception()
                self.ifs = []
        print(time.time() - t)

        # Managed to load IFs?
        if not len(self.ifs):
            raise Exception("p2p node could not load ifs.")

        # Set machine id.
        t = time.time()
        self.machine_id = await self.load_machine_id(
            "p2pd",
            self.ifs[0].netifaces
        )
        print(time.time() - t)

        # Managed to load machine IDs?
        if self.machine_id in (None, ""):
            raise Exception("Could not load machine id.")

        # Used by TCP punch clients.
        t = time.time()
        await self.load_stun_clients()
        print(time.time() - t)

        # MQTT server offsets for signal protocol.
        if self.conf["sig_pipe_no"]:
            await self.load_signal_pipes()

        # Multiprocess support for TCP punching and NTP sync.
        t = time.time()
        await self.setup_punch_coordination(sys_clock)
        print(time.time() - t)
            
        # Accept TCP punch requests.
        self.start_punch_worker()

        # Start worker that forwards sig proto messages.
        self.start_sig_msg_dispatcher()

        # Simple loop to close idle tasks.
        self.idle_pipe_closer = create_task(
            self.close_idle_pipes()
        )

        # Start the server for the node protocol.
        await self.listen_on_ifs()

        # Build P2P address bytes.
        self.addr_bytes = make_peer_addr(
            self.node_id,
            self.machine_id,
            self.ifs,
            list(self.signal_pipes),
            port=self.listen_port,
            ip=self.conf["listen_ip"]
        )

        # Save a dict version of the address fields.
        try:
            self.p2p_addr = parse_peer_addr(self.addr_bytes)
        except:
            log_exception()
            raise Exception("Can't parse nodes p2p addr.")
        
        print(f"> P2P node = {self.addr_bytes}")

        # Used for setting nicknames for the node.
        self.nick_client = await Nickname(
            self.sk,
            self.ifs,
            sys_clock,
        )
        return self
    
    # Connect to a remote P2P node using a number of techniques.
    async def connect(self, addr_bytes, strategies=P2P_STRATEGIES, conf=P2P_PIPE_CONF):
        if pnp_name_has_tld(addr_bytes):
            pkt = await self.nick_client.fetch(addr_bytes)
            addr_bytes = pkt.value
            addr = parse_peer_addr(addr_bytes)
            assert(isinstance(pkt.vkc, bytes))
            self.auth[addr["node_id"]] = {
                "vk": pkt.vkc,
                "sk": None,
            }
            print(f"pkt vkc = {pkt.vkc}")

        print(f"Connecting to {addr_bytes}")
        pp = self.p2p_pipe(addr_bytes)
        return await pp.connect(strategies, reply=None, conf=conf)

    # Get our node server's address.
    def address(self):
        return self.addr_bytes
    
    # Simple KVS over a few servers.
    # Returns your nickname + a tld designating server.
    async def nickname(self, name, value=None):
        value = value or self.address()
        return await self.nick_client.push(
            name,
            value
        )

