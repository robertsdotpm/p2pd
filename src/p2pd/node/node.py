"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""
import asyncio
import multiprocessing
from aionetiface import *
from .node_defs import *
from .node_utils import *
from .nickname import *
from .node_start import *
from .node_stop import *
from .node_protocol import node_protocol
from ..traversal.traversal_address import *
from ..traversal.traversal_manager import TraversalManager
from ..traversal.plugins.direct_connect.main import DirectConnect
from ..traversal.plugins.get_addr.main import GetAddrPlugin
from ..traversal.plugins.return_addr.main import ReturnAddrPlugin
from ..traversal.plugins.reverse_connect.main import ReverseConnectPlugin
from ..vendor.machine_id import *

# Main class for the P2P node server.
class Node(Daemon):
    def __init__(self, ifs=[], ip=[], port=NODE_PORT, stop_node=None, conf=NODE_CONF):
        super().__init__()
        conf = dict_child(conf, NET_CONF)
        self.__name__ = "P2PNode"
        self.install_path = conf["install_path"] or get_aionetiface_install_root()
        self.stop_node = stop_node or multiprocessing.Event()
        self.reachability = {IP4: {}, IP6: {}}
        
        # Main variables for the class.
        self.conf = conf
        self.listen_ips = norm_listen_ips(ip)
        self.listen_port = port
        self.ifs = ifs

        # Handlers for the node protocol.
        self.msg_cbs = []

        # Main pipe connections.
        self.pipes = {} # by pipe_id
        self.turn_clients = {} # by pipe_id
        self.signal_pipes = {} # by MQTT_SERVERS index

        # Pending TCP punch queue.
        self.pp_executor = None

        # Fixed reference for long-running tasks.
        self.tasks = []

        # Watch for idle connections.
        self.last_recv_table = {} # [pipe] -> time
        self.last_recv_queue = [] # FIFO pipe ref

        self.punch_clients = {}
        self.punch_proc = {}
        self.active_punchers = 0

        # Set on start.
        self.addr_bytes = None
        self.addr_futures = {}
        self.traversal = TraversalManager(self.stop_node, self.pipes, self.ifs)
        self.traversal.install_plugin("direct_connect", {
            "class": DirectConnect
        })  
        self.traversal.install_plugin("get_addr", {
            "class": GetAddrPlugin
        })
        self.traversal.install_plugin("return_addr", {
            "class": ReturnAddrPlugin
        })
        self.traversal.install_plugin("reverse_connect", {
            "class": ReverseConnectPlugin
        })

        def on_done(future):
            result = future.result()
            pipe_like = (Pipe, PipeClient, TCPClientProtocol, PipeEvents)
            if isinstance(result, pipe_like):
                print("add msg cb ", result, self.msg_cb)
                result.add_msg_cb(self.msg_cb)

        self.traversal.install_plugin_done_callback(on_done)

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

        # Run msg_cbs across messages.
        msgs = msg.split(b"\n")
        coros = []
        for msg in msgs:
            # node_protocol returns a coroutine
            coros.append(node_protocol(self, msg, client_tup, pipe))

            # wrap msg_cbs as coroutines
            for msg_cb in self.msg_cbs:
                coros.append(msg_cb(msg, client_tup, pipe))

        # Run all coroutines concurrently, collect exceptions instead of propagating
        results = await asyncio.gather(*coros, return_exceptions=True)

        # Handle exceptions.
        for r in results:
            if isinstance(r, KeyboardInterrupt):
                log("reraising key interrupt")
                raise r
            else:
                log(r)

    async def start(self, sys_clock=None, out=False, cout=print):
        await node_start(self, sys_clock=sys_clock, out=out, cout=cout)
        return self
    
    async def close(self):
        if not shut_down.is_set():
            shut_down.set()
            
        await node_stop(self)
    
    def __await__(self):
        return self.start().__await__()
    
    # Connect to a remote P2P node using a number of techniques.
    async def connect(self, af, route_type, pnp_addr, plugin_name=None):
        # TODO: vk lookup map for node ids -- still relevant?
        # todo make vk pass on properly for updated addr msg

        # Get most recent address bytes if given a nickname.
        dest_vk = None
        if pnp_name_has_tld(pnp_addr):
            pkt = await self.nick_client.get(pnp_addr)
            addr_bytes = pkt.value
            dest_vk = pkt.vkc
            print("Dest addr res from namebump = ", pkt.value)
            print(dest_vk)

            try:
                updated_addr_bytes = await asyncio.wait_for(
                    get_updated_addr_from_mqtt(self, addr_bytes),
                    timeout=3
                )
                print("Got updated addr bytes from mqtt = ", updated_addr_bytes)
                if updated_addr_bytes:
                    addr_bytes = updated_addr_bytes
            except asyncio.TimeoutError:
                print("Unable to get updated addr bytes from mqtt")
                log("Timeout MQTT get updated bytes " + str(pnp_addr))
        else:
            addr_bytes = pnp_addr

        # If af is None select an AF supported by both.
        src_map = self.p2p_addr
        dest_map = parse_node_addr(addr_bytes)
        if dest_vk: dest_map["vk"] = dest_vk
        if not af:
            for try_af in (IP4, IP6,):
                if len(src_map[try_af]) and len(dest_map[try_af]):
                    af = try_af
                    break
        
        # No shared AF found.
        if not af:
            raise Exception("No supported shared AF.")

        # Start the traversal plugin method.
        plugin = await self.traversal.start(
            src_map=src_map,
            dest_map=dest_map,
            plugin_name=plugin_name,
            af=af,
            route_type=route_type,
        )

        return plugin

    # Get our node server's address.
    def address(self):
        return self.addr_bytes
    
    # Simple KVS over a few servers.
    # Returns your nickname + a tld designating server.
    async def nickname(self, name, value=None):
        value = value or self.address()
        name = await self.nick_client.put(
            name,
            value
        )

        msg = fstr("Setting nickname '{0}' = '{1}'", (name, value,))
        #log_p2p(msg, self.node_id[:8])
        return name

    def log(self, t, m):
        node_id = self.node_id[:8]
        msg = fstr("{0}: <{1}> {2}", (t, node_id, m,))
        log(msg)

    # Return supported AFs based on all NICs for the node.
    def supported(self):
        afs = set()
        for nic in self.ifs:
            for af in nic.supported():
                afs.add(af)

        # Make IP4 earliest in the list.
        return sorted(tuple(afs))

    async def listen_on_ifs(self):
        # Multi-iface connection facilitation.
        for nic in self.ifs:
            """
            Given a list of IP strings to listen on listen on all IPs
            that match a given interface.
            """
            if self.listen_ips:
                listen_iprs = [IPR(ip) for ip in self.listen_ips]
                for nic_ipr in nic:
                    if nic_ipr not in listen_iprs:
                        continue

                    route = await nic_ipr.route.bind(
                        port=self.listen_port
                    )

                    await async_wrap_errors(
                        self.add_listener(TCP, route)
                    )

                # Don't process the following the listen statements.
                continue
                        
            # Listen on first route for AFs.
            out = await async_wrap_errors(
                self.listen_local(
                    TCP,
                    self.listen_port,
                    nic
                )
            )

            # Add global address listener.
            if IP6 in nic.supported():
                route = await nic.route(IP6).bind(
                    port=self.listen_port
                )

                out = await async_wrap_errors(
                    self.add_listener(TCP, route)
                )

    def pipe_future(self, pipe_id):
        if pipe_id not in self.pipes:
            self.pipes[pipe_id] = asyncio.Future()

        return pipe_id

    def pipe_ready(self, pipe_id, pipe):
        if pipe_id not in self.pipes:
            log(fstr("pipe ready for non existing pipe {0}!", (pipe_id,)))
            return
        
        if not self.pipes[pipe_id].done():
            self.pipes[pipe_id].set_result(pipe)
        
        return pipe

    async def load_machine_id(self, app_id, netifaces):
        # Set machine id.
        try:
            return hashed_machine_id(app_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            return await fallback_machine_id(
                netifaces,
                app_id
            )

    async def remote_reachability_cb(self, msg, client_tup, pipe):
        try:
            # P2PD.net server IPs
            p2pd_ips = (
                IPR("2607:5300:60:80b0::1", af=IP6), 
                IPR("158.69.27.176", af=IP4),
            )

            # Check for eply from p2pd.net for port reachability.
            client_ip = IPR(client_tup[0], af=pipe.route.af)
            if client_ip not in p2pd_ips:
                return

            # Set reply future for interface and AF.
            nic = pipe.route.interface
            af = pipe.route.af
            if nic.id in self.reachability[af]:
                future = self.reachability[af][nic.id]
                if not future.done():
                    future.set_result(True)
        except Exception:
            log("unknown exception in reachability cb")
            log_exception()

    # Accomplishes port forwarding and pin hole rules.
    async def forward(self, port):
        # Run all forwarding tasks concurrently.
        tasks = []
        for nic in self.ifs:
            for af in nic.supported():
                # Add forwarding task.
                async def do_forward(af, nic):
                    # Future where replies will be returned.
                    self.reachability[af][nic.id] = asyncio.Future()
                    route = await nic.route(af).bind()
                    ret = await route.forward(port=port)
                    if ret:
                        return [af, nic.id]

                tasks.append(do_forward(af, nic))

        # Do all the forwarding tasks concurrently.
        forward_success = await asyncio.gather(*tasks, return_exceptions=True)
        forward_success = strip_none(forward_success)
        #print(forward_success)

        # Give enough time for forwarding to be done.
        test_addr = {
            IP4: "158.69.27.176",
            IP6: "2607:5300:60:80b0::1",
        }

        # Now trigger forwarding tests from p2pd.net.
        # My HTTP client sucks so this prob won't even work.
        async def reachability_test(af, nic, port, test_addr):
            # Setup the HTTP client.
            route = nic.route(af)
            dest = (test_addr[af], 80)
            curl = WebCurl(dest, route, do_close=0)

            # Trigger the server to test the service reachability.
            # Get uses conf=NET_CONF = 2 sec recv and con TCP timeout.
            try:
                await curl.vars({
                    "action": "hello",
                    "proto": "tcp",
                    "port": str(port)
                }).get("/p2pd/net_debug.php")
            except asyncio.TimeoutError:
                return None

        # Build reachability tests after forwarding.
        tasks = []
        for nic in self.ifs:
            for af in nic.supported():
                task = reachability_test(af, nic, port, test_addr)
                tasks.append(task)

        # Run reachability tests.
        await asyncio.gather(*tasks, return_exceptions=True)

        # Give enough time for the server response to arrive.
        await asyncio.sleep(2)

        # Return reachability results
        reachable = []
        for af in (IP4, IP6):
            for nic_id in self.reachability[af]:
                if self.reachability[af][nic_id].done():
                    reachable.append((af, nic_id))

        return forward_success, reachable
