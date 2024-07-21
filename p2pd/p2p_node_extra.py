import asyncio
from .settings import *
from .machine_id import hashed_machine_id
from .tcp_punch import *
from .signaling import *
from .p2p_addr import *
from .p2p_utils import *
from .p2p_defs import *
from .p2p_pipe import *

class P2PUtils():
    def p2p_pipe(self, dest_bytes, reply=None, conf=P2P_PIPE_CONF):
        return P2PPipe(dest_bytes, self, reply, conf=conf)

    def cleanup_multiproc(self):
        targets = [self.mp_manager, self.pp_executor]
        for target in targets:
            if target is None:
                continue

            try:
                target.shutdown()
            except:
                continue

        self.mp_manager = None
        self.pp_executor = None

    # Shutdown the node server and do cleanup.
    async def close(self):
        # Stop node server.
        await super().close()

        # Make the worker thread for punching end.
        self.punch_queue.put_nowait([])

        pipe_lists = [
            self.signal_pipes,
            self.tcp_punch_clients,
            self.turn_clients,
            self.pipes,
        ]

        for pipe_list in pipe_lists:
            for pipe in pipe_list.values():
                if pipe is None:
                    continue

                await pipe.close()

        # Try close the multiprocess manager.
        self.cleanup_multiproc()

        """
        Node close will throw: 
        Exception ignored in: <function BaseEventLoop.__del__
        with socket error -1

        So you need to make sure to wrap coroutines for exceptions.
        """
        await asyncio.sleep(.25)

    async def await_peer_con(self, msg, dest, timeout=10):
        # Used to relay signal proto messages.
        signal_pipe = self.find_signal_pipe(dest)
        if signal_pipe is None:
            signal_pipe = await new_peer_signal_pipe(
                dest,
                self
            )
            assert(signal_pipe is not None)


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

    def pipe_future(self, pipe_id):
        print(f"pipe future {pipe_id}")
        pipe_id = pipe_id
        self.pipes[pipe_id] = asyncio.Future()
        return pipe_id

    def pipe_ready(self, pipe_id, pipe):
        print(f"pipe ready {pipe_id}")
        if not self.pipes[pipe_id].done():
            self.pipes[pipe_id].set_result(pipe)
        
        return pipe

    def add_punch_meeting(self, params):
        # Schedule the TCP punching.
        self.punch_queue.put_nowait(params)

    async def punch_queue_worker(self):
        while 1:
            try:
                params = await self.punch_queue.get()
                if not len(params):
                    return

                print("do punch ")
                punch_offset = params.pop(0)

                punch = self.tcp_punch_clients[punch_offset]

                print(params)
                await punch.proto_do_punching(*params)
                print("punch done")
            except:
                log_exception()

    async def schedule_punching_with_delay(self, if_index, pipe_id, node_id, n=0):
        # Get reference to punch client and state.
        punch = self.tcp_punch_clients[if_index]
        state = punch.get_state_info(node_id, pipe_id)
        if state is None:
            log("State none in punch with delay.")
            return

        # Return on timeout or on update.
        if n:
            try:
                await asyncio.wait_for(
                    state["data"]["update_event"].wait(),
                    n
                )
            except:
                # Attempt punching with default ports.
                log("Initiator punch update timeout.")

        # Ready to do the punching process.
        self.add_punch_meeting([
            if_index,
            PUNCH_INITIATOR,
            node_id,
            pipe_id,
        ])

    def start_punch_worker(self):
        task = asyncio.ensure_future(
            self.punch_queue_worker()
        )
        self.tasks.append(task)

    async def load_stun_clients(self):
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

    async def listen_on_ifs(self, protos=[TCP]):
        # Make a list of routes based on supported address families.
        routes = []
        if_names = []
        for interface in self.ifs:
            for af in interface.supported():
                route = await interface.route(af).bind()
                routes.append(route)

            if_names.append(interface.name)

        # Start handling messages for self.msg_cb.
        # Bind to all ifs provided to class on route[0].
        task = await self.listen_all(
            routes,
            [self.port],
            protos
        )
        self.tasks.append(task)

    async def load_machine_id(self, app_id, netifaces):
        # Set machine id.
        try:
            return hashed_machine_id(app_id)
        except:
            return await fallback_machine_id(
                netifaces,
                app_id
            )
        
    async def load_signal_pipe(self, offsets, attempts=2):
        count = 0
        while not offsets.empty():
            count += 1
            if count >= attempts:
                return
            
            offset = await offsets.get()
            mqtt_server = MQTT_SERVERS[offset]
            signal_pipe = SignalMock(
                peer_id=to_s(self.node_id),
                f_proto=self.signal_protocol,
                mqtt_server=mqtt_server
            )

            try:
                await signal_pipe.start()
                self.signal_pipes[offset] = signal_pipe
                return
            except Exception:
                if signal_pipe.is_connected:
                    await signal_pipe.close()

                return None
        
    """
    There's a massive problem with the MQTT client
    library. Starting it must use threading or do
    something funky with the event loop.
    It seems that starting the MQTT clients
    sequentially prevents errors with queues being
    bound to the wrong event loop.

    TODO: investigate this.
    """
    async def load_signal_pipes(self):
        q = asyncio.Queue()
        serv_len = len(MQTT_SERVERS)
        offsets = shuffle(list(range(serv_len)))
        [q.put_nowait(o) for o in offsets]

        tasks = []
        for _ in range(SIGNAL_PIPE_NO):
            task = await self.load_signal_pipe(q)
            #tasks.append(task)

        #await asyncio.gather(*tasks)

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

    def find_signal_pipe(self, addr):
        our_offsets = list(self.signal_pipes)
        for offset in addr["signal"]:
            if offset in our_offsets:
                return self.signal_pipes[offset]

        return None

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
                self,
                self.sys_clock,
                self.pp_executor,
                self.mp_manager
            )
            for interface in self.ifs
        ]

