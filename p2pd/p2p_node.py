
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
    "node_id": None,
    "listen_ip": None,
    "seed": None,
    "enable_upnp": False,
    "sig_pipe_no": SIGNAL_PIPE_NO,
}, NET_CONF)

# Main class for the P2P node server.
class P2PNode(P2PNodeExtra, Daemon):
    def __init__(self, ifs=[], port=NODE_PORT, conf=NODE_CONF):
        self.__name__ = "P2PNode"
        super().__init__()
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
                "vk": self.vk,
            }
        }

    async def add_msg_cb(self, msg_cb):
        self.msg_cbs.append(msg_cb)

    # Used by the node servers.
    async def msg_cb(self, msg, client_tup, pipe):
        await node_protocol(self, msg, client_tup, pipe)
        for msg_cb in self.msg_cb:
            run_handler(pipe, msg_cb, client_tup, msg)
    
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
        if not len(self.ifs):
            if_names = await load_interfaces()
            nics = []
            for if_name in if_names:
                try:
                    nic = await Interface(if_name)
                    await nic.load_nat()
                    nics.append(nic)
                except:
                    log_exception()

            self.ifs = nics


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

        # Start worker that forwards sig proto messages.
        self.start_sig_msg_dispatcher()

        """
        # Check at least one signal pipe was set.
        if not len(self.signal_pipes):
            raise Exception("Unable to get any signal pipes.")
        """

        # Coordination.
        if sys_clock is None:
            sys_clock = await SysClock(self.ifs[0]).start()
        pe = await get_pp_executors()
        qm = multiprocessing.Manager()
        self.setup_multiproc(pe, qm)
        self.setup_coordination(sys_clock)

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
        self.p2p_addr = parse_peer_addr(self.addr_bytes)
        print(f"> P2P node = {self.addr_bytes}")

        # Used for setting nicknames for the node.
        self.nick_client = await Nickname(self.sk, self.ifs[0])

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

