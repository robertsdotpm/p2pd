import secrets
import asyncio
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from decimal import Decimal as Dec
from .p2p_pipe import *
from .daemon import *
from .p2p_protocol_old import *
from .signaling import *
from .machine_id import get_machine_id, hashed_machine_id
from .p2p_utils import *

NODE_CONF = dict_child({
    # Reusing address can hide errors for the socket state.
    # This can make servers appear to be broken when they're not.
    "reuse_addr": False,
}, NET_CONF)

class P2PUtils():
    # Accomplishes port forwarding and pin hole rules.
    async def forward(self, port):
        tasks = []
        for server in self.servers:
            # Get the bind IP and interface for the route.
            route = server[0]

            # Only forward to public IPv6 addresses.
            ipr = IPRange(route.nic())
            if route.af == IP6 and ipr.is_private:
                continue

            # Make task to forward this route.
            task = route.forward(port)
            tasks.append(task)

        # Get a list of tasks to do forwarding or pin holes.
        results = await asyncio.gather(*tasks)
        tasks = []
        for result in results:
            if len(result):
                tasks += result

        # Now do that all at once since it might take a while.
        if len(tasks):
            await asyncio.gather(*tasks)

    # Given a dict of credentials find the associated client.
    def find_turn_client(self, turn_server, af=None, interface=None):
        for turn_client in self.turn_clients:
            # Get credentials for turn client.
            credentials = turn_client.get_turn_server(af=af)

            # Compare credentials to turn_server.
            is_same = find_turn_server(credentials, [turn_server])
            if not is_same:
                continue

            # Not the same interface.
            if interface is not None:
                if turn_client.turn_pipe.route.interface != interface:
                    continue

            # Otherwise found it.
            return turn_client

        return None

    def find_signal_pipe(self, addr):
        our_offsets = list(self.signal_pipes)
        for offset in addr["signal"]:
            if offset in our_offsets:
                return self.signal_pipes[offset]

        return None

    def rm_pipe_id(self, pipe_id):
        def closure(data, client_tup, pipe):
            # Delete reference to pipe.
            log(f"Running rm pipe id {pipe_id}")
            if pipe_id in self.pipes:
                del self.pipes[pipe_id]

        return closure

    def setup_multiproc(self, pp_executor, mp_manager):
        # Process pools are disabled.
        if pp_executor is None:
            self.pp_executor = None
            self.mp_manager = None
            return
            
        assert(mp_manager)
        self.pp_executor = pp_executor
        self.mp_manager = mp_manager

    def setup_coordination(self, sys_clock):
        self.sys_clock = sys_clock

    def setup_tcp_punching(self):
        self.tcp_punch_clients = [
            TCPPunch(
                interface,
                self.ifs,
                self.sys_clock,
                self.pp_executor,
                self.mp_manager
            )
            for interface in self.ifs
        ]

# Main class for the P2P node server.
class P2PNode(Daemon, P2PUtils):
    def __init__(self, ifs, port=NODE_PORT, node_id=None, ip=None, signal_offsets=None, enable_upnp=False, conf=NODE_CONF, seed=None):
        super().__init__()
        self.seed = seed or secrets.token_bytes(24)
        self.conf = conf
        self.signal_offsets = signal_offsets
        self.port = port
        self.enable_upnp = enable_upnp
        self.ip = ip
        self.ifs = ifs
        self.ifs_by_af = {IP4: [], IP6: []}
        for af in VALID_AFS:
            for interface in ifs:
                if af in interface.supported():
                    self.ifs_by_af[af].append(interface)


        self.node_id = node_id or rand_plain(15)
        self.signal_pipes = {} # offset into MQTT_SERVERS
        self.expected_addrs = {} # by [pipe_id]
        self.pipe_events = {} # by [pipe_id]
        self.pipes = {} # by [pipe_id]
        self.sys_clock = None
        self.pp_executor = None
        self.mp_manager = None
        self.tcp_punch_clients = [] # [...]
        self.turn_clients = {}

        # Handlers for the node's custom protocol functions.
        self.msg_cbs = []

        # Maps p2p's ext to pipe_id.
        self.pending_pipes = {} # by [pipe_id]
        self.is_running = True
        self.listen_all_task = None
        self.signal_worker_task = None
        self.signal_worker_tasks = {} # offset into MQTT_SERVERS

        self.punch_queue = asyncio.Queue()
        self.sig_proto_handlers = SigProtoHandlers(self)

    async def await_peer_con(self, msg, signal_pipe, timeout=10):
        await signal_pipe.send_msg(
            msg.pack(),
            to_s(msg.routing.dest["node_id"])
        )

        try:
            return await asyncio.wait_for(
                self.pipes[msg.meta.pipe_id],
                timeout
            )
        except asyncio.TimeoutError:
            return None

    async def make_connection(self, af, pipe_id, node_id, src_info, dest_info, dest_bytes, same_machine=False):
        # (1) Get first interface for AF.
        # (2) Build a 'route' from it with it's main NIC IP.
        # (3) Bind to the route at port 0. Return itself.
        if_index = src_info["if_index"]
        interface = self.ifs[if_index]
        route = await interface.route(af).bind()
        print("in make con")
        print(route)
        print(dest_info["ext"])
        print(dest_info["port"])

        # Connect to this address.
        dest = Address(
            str(dest_info["ext"]),
            dest_info["port"],
        )

        """
        If connecting to a different interface on the same
        machine the connection will only work if the
        interfaces are bridged or there's route table
        rules between them so we instead bind to the dest
        """
        if same_machine:
            if dest_info["nic"] != src_info["nic"]:
                print("yes replace route")
                dest = Address(
                    str(dest_info["nic"]),
                    dest_info["port"]
                )

                route = await interface.route(af).bind(
                    ips=str(dest_info["nic"])
                )

        print(route._bind_tups)
        print(dest.host)

        pipe = await pipe_open(
            route=route,
            proto=TCP,
            dest=dest,
            msg_cb=self.msg_cb
        )

        print(pipe)
        return pipe

    def pipe_future(self, pipe_id=None):
        pipe_id = pipe_id or rand_plain(15)
        self.pipes[pipe_id] = asyncio.Future()
        return pipe_id

    def pipe_ready(self, pipe_id, pipe):
        if not self.pipes[pipe_id].done():
            self.pipes[pipe_id].set_result(pipe)
        return pipe

    def add_punch_meeting(self, params):
        # Allow pipe to be awaited by pipe_id.
        self.pipe_future(params[-1])

        # Schedule the TCP punching.
        self.punch_queue.put_nowait(params)

    async def punch_queue_worker(self):
        while 1:
            params = await self.punch_queue.get()
            if not len(params):
                return

            print("do punch ")
            print(params)
            punch_offset = params.pop(0)
            punch = self.tcp_punch_clients[punch_offset]
            pipe = await punch.proto_do_punching(*params)
            if pipe is not None:
                self.pipe_ready(params[-1], pipe)

    async def schedule_punching_with_delay(self, if_index, pipe_id, node_id, n=2):
        # Get reference to punch client and state.
        punch = self.tcp_punch_clients[if_index]
        state = punch.get_state_info(node_id, pipe_id)
        if state is None:
            log("State none in punch with delay.")
            return

        # Return on timeout or on update.
        try:
            asyncio.wait_for(
                state["data"]["update_event"].wait(),
                n
            )
        except asyncio.TimeoutError:
            # Attempt punching with default ports.
            log("Initiator punch update timeout.")

        # Ready to do the punching process.
        self.add_punch_meeting([
            if_index,
            PUNCH_INITIATOR,
            node_id,
            pipe_id,
        ])

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

    # Used by the node servers.
    async def msg_cb(self, msg, client_tup, pipe):
        return await node_protocol(self, msg, client_tup, pipe)

    # Add custom protocol handlers to node server.
    def add_msg_cb(self, msg_cb):
        self.msg_cbs.append(msg_cb)

    # Del custom protocol handlers from node server.
    def del_msg_cb(self, msg_cb):
        if msg_cb in self.msg_cbs:
            self.msg_cbs.remove(msg_cb)

    async def dev(self, protos=[TCP]):
        # Set machine id.
        try:
            self.machine_id = hashed_machine_id("p2pd")
        except:
            self.machine_id = await fallback_machine_id(
                self.ifs[0].netifaces,
                "p2pd"
            )

        # MQTT server offsets to try.
        if self.signal_offsets is None:
            offsets = [0] + shuffle([i for i in range(1, len(MQTT_SERVERS))])
        else:
            offsets = self.signal_offsets

        # Get list of N signal pipes.
        for offset in range(0, SIGNAL_PIPE_NO):
            self.signal_pipes[offset] = None

        # Make a list of routes based on supported address families.
        routes = []
        if_names = []
        for interface in self.ifs:
            for af in interface.supported():
                route = await interface.route(af).bind()
                routes.append(route)

            if_names.append(interface.name)

        # Do deterministic bind to port by NIC IPs.
        if self.port == -1:
            self.port = get_port_by_ips(if_names)
            for _ in range(0, 2):
                try:
                    self.listen_all_task = await self.listen_all(
                        routes,
                        [self.port],
                        protos
                    )
                    break
                except Exception:
                    # Use any port.
                    log(f"Deterministic bind for node server failed.")
                    log(f"Port {self.port} was not available.")
                    self.port = 0
                    log_exception()
        else:
            # Start handling messages for self.msg_cb.
            # Bind to all ifs provided to class on route[0].
            self.listen_all_task = await self.listen_all(
                routes,
                [self.port],
                protos
            )

        # Translate any port 0 to actual assigned port.
        # First server, field 3 == base_proto.
        # sock = listen sock, getsocketname = (bind_ip, bind_port, ...)
        port = self.servers[0][2].sock.getsockname()[1]
        print(f"Server port = {port}")

        self.addr_bytes = make_peer_addr(self.node_id, self.machine_id, self.ifs, list(self.signal_pipes), port=port, ip=self.ip)
        self.p2p_addr = parse_peer_addr(self.addr_bytes)
        print(f"> P2P node = {self.addr_bytes}")
        print(self.p2p_addr)

        self.punch_worker = asyncio.ensure_future(
            self.punch_queue_worker()
        )

        # TODO: placeholder.
        self.stun_clients = {IP4: {}, IP6: {}}
        for af in VALID_AFS:
            for if_index in range(0, len(self.ifs)):
                interface = self.ifs[if_index]
                if af in interface.supported():
                    self.stun_clients[af][if_index] = (await get_stun_clients(
                        af,
                        1,
                        interface,
                        TCP,
                        conf=PUNCH_CONF
                    ))[0]
            
        return self

    # Start the node -- must have been setup properly first.
    async def start(self, protos=[TCP]):
        # MQTT server offsets to try.
        if self.signal_offsets is None:
            offsets = [0] + shuffle([i for i in range(1, len(MQTT_SERVERS))])
        else:
            offsets = self.signal_offsets

        # Get list of N signal pipes.
        for _ in range(0, SIGNAL_PIPE_NO):
            async def set_signal_pipe(offset):
                mqtt_server = MQTT_SERVERS[offset]
                signal_pipe = SignalMock(
                    peer_id=to_s(self.node_id),
                    f_proto=self.signal_protocol,
                    mqtt_server=mqtt_server
                )

                try:
                    await signal_pipe.start()
                    self.signal_pipes[offset] = signal_pipe
                    return signal_pipe
                except Exception:
                    if signal_pipe.is_connected:
                        await signal_pipe.close()
                    return None
            
            # Traverse list of shuffled server indexes.
            while 1:
                # If tried all then we're done.
                if not len(offsets):
                    break

                # Get the next offset to try.
                offset = offsets.pop(0)

                # Try to use the server at the offset for a signal pipe.
                signal_pipe = await async_wrap_errors(
                    set_signal_pipe(offset)
                )

                # The connection failed so keep trying.
                if signal_pipe is None:
                    continue
                else:
                    break

        # Check at least one signal pipe was set.
        if not len(self.signal_pipes):
            raise Exception("Unable to get any signal pipes.")

        # Make a list of routes based on supported address families.
        routes = []
        if_names = []
        for interface in self.ifs:
            for af in interface.supported():
                route = await interface.route(af).bind()
                routes.append(route)

            if_names.append(interface.name)

        # Do deterministic bind to port by NIC IPs.
        if self.port == -1:
            self.port = get_port_by_ips(if_names)
            for _ in range(0, 2):
                try:
                    self.listen_all_task = await self.listen_all(
                        routes,
                        [self.port],
                        protos
                    )
                    break
                except Exception:
                    # Use any port.
                    log(f"Deterministic bind for node server failed.")
                    log(f"Port {self.port} was not available.")
                    self.port = 0
                    log_exception()
        else:
            # Start handling messages for self.msg_cb.
            # Bind to all ifs provided to class on route[0].
            self.listen_all_task = await self.listen_all(
                routes,
                [self.port],
                protos
            )

        # Translate any port 0 to actual assigned port.
        # First server, field 3 == base_proto.
        # sock = listen sock, getsocketname = (bind_ip, bind_port, ...)
        port = self.servers[0][2].sock.getsockname()[1]
        self.addr_bytes = make_peer_addr(self.node_id, self.machine_id, self.ifs, list(self.signal_pipes), port=port, ip=self.ip)
        self.p2p_addr = parse_peer_addr(self.addr_bytes)
        log(f"> P2P node = {self.addr_bytes}")

        # Do port forwarding if enabled.
        # Maybe this should go in the route class?
        if self.enable_upnp:
            # UPnP has no unit tests so wrap all errors for now.
            await async_wrap_errors(
                self.forward(port)
            )

        self.punch_worker = asyncio.ensure_future(
            self.punch_queue_worker()
        )
            
        return self

    # Connect to a remote P2P node using a number of techniques.
    async def connect(self, addr_bytes, strategies=P2P_STRATEGIES, timeout=60):
        # Create a TCP connection to the peer using the strategies
        # defined in the strategies list.
        p2p_pipe = P2PPipe(self)
        return await p2p_pipe.pipe(
            addr_bytes,
            strategies=strategies,
            timeout=timeout
        )
    
    """
    Register this name on up to N IRC servers if needed.
    Then set the value at that name to this nodes address
    """
    async def register(self, name_field):
        pass

    # Get our node server's address.
    def address(self):
        return self.addr_bytes

    # Shutdown the node server and do cleanup.
    async def close(self):
        # Stop node server.
        await super().close()
        self.is_running = False

        # Make the worker thread for punching end.
        self.punch_queue.put_nowait([])

        # Close the MQTT client.
        for offset in list(self.signal_pipes):
            signal_pipe = self.signal_pipes[offset]
            if signal_pipe is None:
                continue

            await signal_pipe.close()

        # Close TCP punch clients.
        for punch_client in self.tcp_punch_clients:
            if punch_client is None:
                continue

            # Sets close event.
            # Waits for stop event.
            await punch_client.close()

        # Close TURN clients.
        for pipe_id in self.turn_clients:
            # Sets state transition to error state to end msg check loop.
            # Closes the open TURN client handle.
            turn_client = self.turn_clients[pipe_id]
            if turn_client is not None:
                await turn_client.close()

        # Cancel all pending p2p_pipes from this node.
        for pipe_task in self.pending_pipes.values():
            pipe_task.cancel()

        """
        Close all open pipes. These may be a mixture of
        inbound cons, outbound cons, servers, or various
        clients. Anything already closed will return.
        """
        for pipe in self.pipes.values():
            await pipe.close()

        # Try close the multiprocess manager.
        try:
            if self.mp_manager is not None:
                self.mp_manager.shutdown()
        except Exception:
            pass

        # Try close the process pool executor.
        try:
            if self.pp_executor is not None:
                self.pp_executor.shutdown()
        except Exception:
            pass

        """
        Node close will throw: 
        Exception ignored in: <function BaseEventLoop.__del__
        with socket error -1

        So you need to make sure to wrap coroutines for exceptions.
        """
        self.mp_manager = None
        self.pp_executor = None
        await asyncio.sleep(.25)

# delay with sys clock and get_pp_executors.
async def start_p2p_node(port=NODE_PORT, node_id=None, ifs=None, 
                         clock_skew=Dec(0), ip=None, pp_executors=False, enable_upnp=False, signal_offsets=None, netifaces=None):
    netifaces = netifaces or Interface.get_netifaces()
    if netifaces is None:
        netifaces = await init_p2pd()

    # Load NAT info for interface.
    ifs = ifs or await load_interfaces(netifaces=netifaces)
    assert(len(ifs))
    for interface in ifs:
        # Don't set NAT details if already set.
        if interface.resolved:
            continue

        # Prefer IP4 if available.
        af = IP4
        if af not in interface.supported():
            af = IP6

        # STUN is used to test the NAT.
        stun_client = STUNClient(
            interface,
            af
        )

        # Load NAT type and delta info.
        # On a server should be open.
        nat = await stun_client.get_nat_info()
        interface.set_nat(nat)

    if pp_executors is None:
        pp_executors = await get_pp_executors(workers=4)

    if clock_skew == Dec(0):
        sys_clock = await SysClock(ifs[0]).start()
    else:
        sys_clock = SysClock(ifs[0], clock_skew)

    # Log sys clock details.
    assert(sys_clock.clock_skew) # Must be set for meetings!
    log(f"> Start node. Clock skew = {sys_clock.clock_skew}")

    # Pass interface list to node.
    node = await async_wrap_errors(
        P2PNode(
            if_list=ifs,
            port=port,
            node_id=node_id,
            ip=ip,
            signal_offsets=signal_offsets,
            enable_upnp=enable_upnp
        ).start()
    )

    log("node success apparently.")

    # Configure node for TCP punching.
    if pp_executors is not None:
        mp_manager = multiprocessing.Manager()
    else:
        mp_manager = None

    node.setup_multiproc(pp_executors, mp_manager)
    node.setup_coordination(sys_clock)
    node.setup_tcp_punching()

    # Wait for MQTT sub.
    for offset in list(node.signal_pipes):
        await node.signal_pipes[offset].sub_ready.wait()

    return node

if __name__ == "__main__": # pragma: no cover
    from .p2p_pipe import P2PPipe, P2P_DIRECT, P2P_REVERSE, P2P_PUNCH, P2P_RELAY
    from .nat import *
    async def test_p2p_node():
        sys_clock = SysClock(Dec("-0.02839018452552057081653225806"))
        pp_executor = ProcessPoolExecutor()
        mp_manager = multiprocessing.Manager()
        #internode_out = await Interface("enp3s0").start()
        starlink_out = await Interface("wlp2s0").start()
        internode_nat = nat_info(PRESERV_NAT, delta_info(PRESERV_NAT, 0))
        starlink_nat = nat_info(RESTRICT_PORT_NAT, delta_info(RANDOM_DELTA, 0), [34000, MAX_PORT])
        #internode_out.set_nat(internode_nat)
        starlink_out.set_nat(starlink_nat)





        alice_node = await P2PNode([starlink_out], 11111).start()
        alice_node.setup_multiproc(pp_executor, mp_manager)
        alice_node.setup_coordination(sys_clock)
        alice_node.setup_tcp_punching()

        
        bob_node = await P2PNode([starlink_out], 22222).start()
        bob_node.setup_multiproc(pp_executor, mp_manager)
        bob_node.setup_coordination(sys_clock)
        bob_node.setup_tcp_punching()
        alice_p2p_pipe = P2PPipe(alice_node)
        

        #print(alice_node.tcp_punch_clients[0].interface.route(IP4))



        """
        print("Testing direct connect.")
        direct_pipe = await alice_p2p_pipe.pipe(
            bob_node.addr_bytes,
            [P2P_DIRECT]
        )
        print(direct_pipe)
        """

        """
        print("Testing reverse connect.")
        reverse_pipe = await alice_p2p_pipe.pipe(
            bob_node.addr_bytes,
            [P2P_REVERSE]
        )
        print(reverse_pipe)
        """

        """
        print("Testing p2p punch.")
        punch_pipe = await alice_p2p_pipe.pipe(
            bob_node.addr_bytes,
            [P2P_PUNCH]
        )
        """

        print("Testing p2p relay.")
        relay_pipe = await alice_p2p_pipe.pipe(
            bob_node.addr_bytes,
            [P2P_RELAY]
        )

        print("Got this pipe from relay = ")
        print(relay_pipe)
        
        await relay_pipe.send(b"Test msg back to bob via turn chan.")   
        print("sent")
        while 1:
            await asyncio.sleep(1)

    async_test(test_p2p_node)

