import asyncio
from .settings import *
from .machine_id import hashed_machine_id
from .tcp_punch import TCPPunch, PUNCH_CONF
from .tcp_punch import PUNCH_INITIATOR
from .p2p_utils import *
from .p2p_pipe import *
from .signaling import *
from .stun_client import get_stun_clients
from .nat import USE_MAP_NO

class P2PNodeExtra():
    async def load_stun_clients(self):
        self.stun_clients = {IP4: {}, IP6: {}}
        for af in VALID_AFS:
            for if_index in range(0, len(self.ifs)):
                interface = self.ifs[if_index]
                if af in interface.supported():
                    self.stun_clients[af][if_index] = await get_n_stun_clients(
                        af=af,
                        n=USE_MAP_NO + 2,
                        interface=interface,
                        proto=TCP,
                        conf=PUNCH_CONF,
                    )

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
        return
        for index in range(len(self.ifs)):
            interface = self.ifs[index]
            self.tcp_punch_clients[index] = TCPPunch(
                interface,
                self.ifs,
                self,
                self.sys_clock,
                self.pp_executor,
                self.mp_manager
            )

    async def punch_queue_worker(self):
        try:
            params = await self.punch_queue.get()
            if params is None:
                print("closing punch queue worker")
                return
            
            print("do punch ")

            pipe_id = params[0]
            puncher = self.tcp_punch_clients[pipe_id]

            await async_wrap_errors(
                puncher.setup_punching_process()
            )
            print("punch done")

            self.punch_worker_task = asyncio.ensure_future(
                self.punch_queue_worker()
            )
        except RuntimeError:
            print("punch queue worker run time error")
            return

    def start_punch_worker(self):
        print("in start punch worker")
        self.punch_worker_task = asyncio.ensure_future(
            self.punch_queue_worker()
        )

    def add_punch_meeting(self, params):
        # Schedule the TCP punching.
        self.punch_queue.put_nowait(params)

    async def schedule_punching_with_delay(self, pipe_id, n=2):
        await asyncio.sleep(n)

        # Ready to do the punching process.
        self.add_punch_meeting([
            pipe_id,
        ])

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
        sig_pipe_no = self.conf["sig_pipe_no"]
        for _ in range(sig_pipe_no):
            task = self.load_signal_pipe(q)
            tasks.append(task)

        await asyncio.gather(*tasks)
    
    def find_signal_pipe(self, addr):
        our_offsets = list(self.signal_pipes)
        for offset in addr["signal"]:
            if offset in our_offsets:
                return self.signal_pipes[offset]

        return None

    async def listen_on_ifs(self, protos=[TCP]):
        # Make a list of routes by supported AF.
        routes = []
        if_names = []
        for interface in self.ifs:
            for af in interface.supported():
                route = interface.route(af)
                route = await route.bind(
                    port=self.listen_port,
                    ips=self.conf["listen_ip"]
                )
                assert(route is not None)

                routes.append(route)

            if_names.append(interface.name)

        # Start handling messages for self.msg_cb.
        # Bind to all ifs provided to class on route[0].
        task = await self.listen_all(
            routes,
            [self.listen_port],
            protos
        )
        self.tasks.append(task)

    def pipe_future(self, pipe_id):
        if pipe_id not in self.pipes:
            self.pipes[pipe_id] = asyncio.Future()

        return pipe_id

    def pipe_ready(self, pipe_id, pipe):
        if not self.pipes[pipe_id].done():
            self.pipes[pipe_id].set_result(pipe)
        
        return pipe

    async def await_peer_con(self, msg, timeout=10):
        # Used to relay signal proto messages.
        signal_pipe = self.find_signal_pipe(msg.routing.dest)
        if signal_pipe is None:
            signal_pipe = await new_peer_signal_pipe(
                msg.routing.dest,
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
        
    async def sig_msg_dispatcher(self):
        try:
            msg = await self.sig_msg_queue.get()
            if msg is None:
                return
            
            await self.await_peer_con(
                msg
            )

            self.sig_msg_dispatcher_task = asyncio.ensure_future(
                self.sig_msg_dispatcher()
            )
        except RuntimeError:
            what_exception()
            return
        
    def start_sig_msg_dispatcher(self):
        # Route messages to destination.
        if self.sig_msg_dispatcher_task is None:
            self.sig_msg_dispatcher_task = asyncio.ensure_future(
                self.sig_msg_dispatcher()
            )

    async def load_machine_id(self, app_id, netifaces):
        # Set machine id.
        try:
            return hashed_machine_id(app_id)
        except:
            return await fallback_machine_id(
                netifaces,
                app_id
            )

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

    def p2p_pipe(self, dest_bytes):
        return P2PPipe(dest_bytes, self)

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
        print("in close")
        # Make the worker thread for punching end.
        self.punch_queue.put_nowait(None)
        if self.punch_worker_task is not None:
            self.punch_worker_task.cancel()
            self.punch_worker_task = None

        # Stop sig message dispatcher.
        self.sig_msg_queue.put_nowait(None)
        if self.sig_msg_dispatcher_task is not None:
            self.sig_msg_dispatcher_task.cancel()
            self.sig_msg_dispatcher_task = None

        # Close other pipes.
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

                if isinstance(pipe, asyncio.Future):
                    if pipe.done():
                        pipe = pipe.result()
                    else:
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

        # Stop node server.
        await super().close()

        await asyncio.sleep(.25)