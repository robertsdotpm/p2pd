import asyncio
from .p2p_utils import *
from .p2p_addr import *
from .tcp_punch import *
from .p2p_pipe import *

async def new_peer_signal_pipe(p2p_dest, node):
    for offset in p2p_dest["signal"]:
        # Build a channel to relay signal messages to peer.
        mqtt_server = MQTT_SERVERS[offset]
        signal_pipe = SignalMock(
            peer_id=to_s(node.node_id),
            f_proto=node.signal_protocol,
            mqtt_server=mqtt_server
        )

        print(signal_pipe)

        # If it fails unset the client.
        try:
            # If it's successful exit server offset attempts.
            await signal_pipe.start()
            node.signal_pipes[offset] = signal_pipe
        except asyncio.TimeoutError:
            print("sig pipe timeout")
            # Cleanup and make sure it's unset.
            await signal_pipe.close()
            continue

        return signal_pipe

class NodeUtils():
    async def ifs_listen_all(self, port, protos):
        # Make a list of routes based on stack.
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
            [port],
            protos
        )
        self.tasks.append(task)

    async def start_punch_queue_worker(self):
        task = asyncio.ensure_future(
            self.punch_queue_worker()
        )
        self.tasks.append(task)

    # by [af][if_index]
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

    async def load_signal_pipes(self):
        # MQTT server offsets to try.
        serv_no = len(MQTT_SERVERS)
        offsets = shuffle(list(range(serv_no)))
        offset_queue = asyncio.Queue()
        [offset_queue.put_nowait(o) for o in offsets]
        
        """
        The worker pulls an offset from the list above.
        Returns immediately on success or until offset
        list has been emptied. Concurrent algorithm is
        potentially faster than sequentially doing this.
        """
        async def worker(offset_queue, count=0):
            while not offset_queue.empty():
                offset = await offset_queue.get()
                count += 1

                # Load MQTT server -- and sub to node ID.
                mqtt_server = MQTT_SERVERS[offset]
                signal_pipe = SignalMock(
                    peer_id=to_s(self.node_id),
                    f_proto=self.signal_protocol,
                    mqtt_server=mqtt_server
                )

                # Start the MQTT client.
                try:
                    await signal_pipe.start()
                    self.signal_pipes[offset] = signal_pipe
                except Exception:
                    # Ensure broken clients are closed.
                    if signal_pipe.is_connected:
                        await signal_pipe.close()
                    
                    # Log the exception.
                    log_exception()
                    if count >= 3:
                        return
                    
                    continue

                return
            
        # Concurrently load signal pipes.
        tasks = []
        for _ in range(SIGNAL_PIPE_NO):
            tasks.append(worker(offset_queue))

        await asyncio.gather(*tasks)
        if not len(self.signal_pipes):
            raise Exception("Unable to get signal pipes.")

    def p2p_pipe(self, dest_bytes, reply=None, conf=P2P_PIPE_CONF):
        return P2PPipe(dest_bytes, self, reply, conf=conf)

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

    def cleanup_multiproc(self):
        for x in [self.mp_manager, self.pp_executor]:
            if x is None:
                continue

            try:
                x.shutdown()
            except:
                continue

        self.mp_manager = None
        self.pp_executor = None

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

    # Shutdown the node server and do cleanup.
    async def close(self):
        # Stop node server.
        await super().close()

        # Make the worker thread for punching end.
        self.punch_queue.put_nowait([])

        # All have the same close interface.
        # Note pipes may shadow turn_clients.
        pipes_dicts = [
            self.signal_pipes,
            self.turn_clients,
            self.pipes,
            #self.tcp_punch_clients,
        ]

        for pipe_dict in pipes_dicts:
            for pipe in pipe_dict.values():
                if pipe is None:
                    continue

                await pipe.close()

        self.cleanup_multiproc()

        """
        Node close will throw: 
        Exception ignored in: <function BaseEventLoop.__del__
        with socket error -1

        So you need to make sure to wrap coroutines for exceptions.
        """
        await asyncio.sleep(.25)