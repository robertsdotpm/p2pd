"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""
import asyncio
import hashlib
from ..nic.interface import load_interfaces
from ..nic.select_interface import list_interfaces
from ..net.daemon import *
from .node_addr import *
from .node_utils import *
from .node_extra import *
from .nickname import *
from ..traversal.tunnel_address import *
from ..traversal.signaling.signaling_protocol import *

NODE_CONF = dict_child({
    "reuse_addr": False,
    "enable_upnp": True,
    "sig_pipe_no": SIGNAL_PIPE_NO,
}, NET_CONF)

# Main class for the P2P node server.
class P2PNode(P2PNodeExtra, Daemon):
    def __init__(self, ifs=[], port=3000, conf=NODE_CONF):
        super().__init__()
        self.__name__ = "P2PNode"
        
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

        # Watch for idle connections.
        self.last_recv_table = {} # [pipe] -> time
        self.last_recv_queue = [] # FIFO pipe ref

        # Set on start.
        self.addr_bytes = None
        self.addr_futures = {}

    def add_msg_cb(self, msg_cb):
        self.msg_cbs.append(msg_cb)

    # Used by the node servers.
    async def msg_cb(self, msg, client_tup, pipe):
        """
        TCP is stream-orientated and may buffer small sends.
        New lines end messages. So multiple messages can
        be read by splitting at a new line. Excluding
        complex cases of partial replies (who cares for now.)

        TODO: implement actual buffered protocol.
        """

        # Recv a message for a pipe being monitored for idleness.
        if pipe in self.last_recv_queue:
            self.last_recv_table[pipe.sock] = time.time()

        msgs = msg.split(b"\n")
        for msg in msgs:
            # Pass messages directly to clients own handlers.
            # Don't interfere so they can write their own protocol.
            await node_protocol(self, msg, client_tup, pipe)
            for msg_cb in self.msg_cbs:
                run_handler(pipe, msg_cb, client_tup, msg)

    async def start(self, sys_clock=None, out=False):
        # Load ifs.
        t = time.time()
        if not len(self.ifs):
            try:
                if_names = await list_interfaces()
                self.ifs = await load_interfaces(if_names, Interface)
            except:
                log_exception()
                self.ifs = []

        # Make sure ifs are in the same order.
        self.ifs = sorted(self.ifs, key=lambda x: x.name)

        # Managed to load IFs?
        if not len(self.ifs):
            raise Exception("p2p node could not load ifs.")

        # Set machine id.
        t = time.time()
        self.machine_id = await self.load_machine_id(
            "p2pd",
            self.ifs[0].netifaces
        )

        # Managed to load machine IDs?
        if self.machine_id in (None, ""):
            raise Exception("Could not load machine id.")
        
        """
        The listen port is set deterministically to avoid conflicts
        with port forwarding with multiple nodes in the LAN.
        """
        if self.listen_port is None:
            self.listen_port = field_wrap(
                dhash(self.machine_id),
                [10000, 60000]
            )

        # Cryptography for authenticated messages.
        self.sk = self.load_signing_key()
        print("sk:", self.sk)

        self.vk = self.sk.verifying_key
        print("vk:", self.vk)

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

        # Used by TCP punch clients.
        t = time.time()
        if out: print("\tLoading STUN clients...")
        await self.load_stun_clients()
        if out:
            buf = ""
            for if_index in range(0, len(self.ifs)):
                nic = self.ifs[if_index]
                buf += "\t\t" + nic.name + " "
                for af in nic.supported():
                    af_txt = "V4" if af is IP4 else "V6"
                    buf += fstr("({0}={1})", (
                        af_txt, 
                        str(len(self.stun_clients[af][if_index])),
                    ))
                buf += "\n"
            print(buf)

        # MQTT server offsets for signal protocol.
        if self.conf["sig_pipe_no"]:
            if out: print("\tLoading MQTT clients...")
            await self.load_signal_pipes(self.node_id)
            if out:
                buf = "\t\tmqtt = ("
                for index in list(self.signal_pipes):
                    buf += fstr("{0},", (index,))
                buf += ")"
                print(buf)

        if sys_clock is None:
            sys_clock = SysClock(
                interface=self.ifs[0]
            )
            await sys_clock.start()

        # Multiprocess support for TCP punching and NTP sync.
        t = time.time()
        if out: print("\tLoading NTP clock skew...")
        await self.setup_punch_coordination(sys_clock)
        clock_skew = str(self.sys_clock.clock_skew)
        if out: print(fstr("\t\tClock skew = {0}", (clock_skew,)))
            
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

        # Skip port forwarding if all NICs aren't behind NATs.
        all_open_internet = True
        for nic in self.ifs:
            if nic.nat["type"] != OPEN_INTERNET:
                all_open_internet = False
                break

        # Port forward all listen servers.
        if self.conf["enable_upnp"] and not all_open_internet:
            if out: print("\tStarting UPnP task...")

            # Put slow forwarding task in the background.
            forward = asyncio.create_task(
                self.forward(self.listen_port)
            )
            self.tasks.append(forward)
            await asyncio.sleep(2)

        # Build P2P address bytes.
        assert(self.node_id is not None)
        self.addr_bytes = make_peer_addr(
            self.node_id,
            self.machine_id,
            self.ifs,
            list(self.signal_pipes),
            port=self.listen_port,
        )

        # Log address.
        msg = fstr("Starting node = '{0}'", (self.addr_bytes,))
        if not out:
            Log.log_p2p(msg, self.node_id[:8])



        # Save a dict version of the address fields.
        try:
            self.p2p_addr = parse_peer_addr(self.addr_bytes)
        except:
            log_exception()
            raise Exception("Can't parse nodes p2p addr.")

        # Used for setting nicknames for the node.
        self.nick_client = await Nickname(
            self.sk,
            self.ifs,
            self.sys_clock,
        )

        nick = await self.nickname(self.node_id)
        print(nick)
        pkt = await self.nick_client.fetch(nick)
        print("nick pkt vkc = ", pkt.vkc)

        return self
    
    def __await__(self):
        return self.start().__await__()
    
    # Connect to a remote P2P node using a number of techniques.
    async def connect(self, pnp_addr, strategies=P2P_STRATEGIES, conf=P2P_PIPE_CONF):
        # Get most recent address bytes if given a nickname.
        if pnp_name_has_tld(pnp_addr):
            addr_bytes = await get_updated_addr_bytes(self, pnp_addr)
        else:
            addr_bytes = pnp_addr

        msg = fstr("Connecting to '{0}'", (addr_bytes,))
        Log.log_p2p(msg, self.node_id[:8])
        pp = self.p2p_pipe(addr_bytes)
        for af in conf["addr_families"]:
            af_conf = copy.deepcopy(conf)
            af_conf["addr_families"] = [af]
            pipe = await pp.connect(strategies, reply=None, conf=af_conf)
            if pipe is not None:
                return pipe
            
        return pipe

    # Get our node server's address.
    def address(self):
        return self.addr_bytes
    
    # Simple KVS over a few servers.
    # Returns your nickname + a tld designating server.
    async def nickname(self, name, value=None):
        value = value or self.address()
        name = await self.nick_client.push(
            name,
            value
        )

        msg = fstr("Setting nickname '{0}' = '{1}'", (name, value,))
        #Log.log_p2p(msg, self.node_id[:8])
        return name

