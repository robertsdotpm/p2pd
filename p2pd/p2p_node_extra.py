
from .settings import *
from .utils import *
from .machine_id import hashed_machine_id
from .tcp_punch_client import PUNCH_CONF
from .p2p_utils import *
from .p2p_pipe import *
from .signaling import *
from .stun_client import get_stun_clients
from .nat_utils import USE_MAP_NO
from .install import *
from .ecies import encrypt, decrypt
import asyncio
import pathlib
from ecdsa import SigningKey, SECP256k1

class P2PNodeExtra():
    def log(self, t, m):
        node_id = self.node_id[:8]
        msg = f"{t}: <{node_id}> {m}"
        log(msg)

    def load_signing_key(self):
        # Make install dir if needed.
        install_root = get_p2pd_install_root()
        pathlib.Path(install_root).mkdir(
            parents=True,
            exist_ok=True
        )

        # Store cryptographic random bytes here for ECDSA ident.
        sk_path = os.path.realpath(
            os.path.join(
                install_root,
                f"SECRET_KEY_DONT_SHARE_{self.listen_port}.hex"
            )
        )

        # Read secret key as binary if it exists.
        if os.path.exists(sk_path):
            with open(sk_path, mode='r') as fp:
                sk_hex = fp.read()

        # Write a new key if the path doesn't exist.
        if not os.path.exists(sk_path):
            sk = SigningKey.generate(curve=SECP256k1)
            sk_buf = sk.to_string()
            sk_hex = to_h(sk_buf)
            with open(sk_path, "w") as file:
                file.write(sk_hex)

        # Convert secret key to a singing key.
        sk_buf = h_to_b(sk_hex)
        sk = SigningKey.from_string(sk_buf, curve=SECP256k1)
        return sk

    async def load_stun_clients(self):
        # Already loaded.
        if hasattr(self, "stun_clients"):
            return
        
        self.stun_clients = {IP4: {}, IP6: {}}
        for if_index in range(0, len(self.ifs)):
            interface = self.ifs[if_index]
            for af in interface.supported():
                self.stun_clients[af][if_index] = await get_n_stun_clients(
                    af=af,
                    n=USE_MAP_NO,
                    interface=interface,
                    proto=TCP,
                    conf=PUNCH_CONF,
                )

    async def punch_queue_worker(self):
        try:
            params = await self.punch_queue.get()
            if params is None:
                return
            
            if len(params):
                pipe_id = params[0]
                if pipe_id in self.tcp_punch_clients:
                    puncher = self.tcp_punch_clients[pipe_id]
                    task = create_task(
                        async_wrap_errors(
                            puncher.setup_punching_process()
                        )
                    )

                    # Avoid garbage collection for this task.
                    self.tasks.append(task)

            self.punch_worker_task = create_task(
                self.punch_queue_worker()
            )
        except RuntimeError:
            return
        except:
            log_exception()
        
    def start_punch_worker(self):
        self.punch_worker_task = create_task(
            self.punch_queue_worker()
        )

    async def setup_punch_coordination(self, sys_clock=None):
        if sys_clock is None:
            sys_clock = await SysClock(self.ifs[0]).start()

        self.max_punchers, self.pp_executor = await get_pp_executors()
        self.sys_clock = sys_clock

    def add_punch_meeting(self, params):
        # Schedule the TCP punching.
        self.punch_queue.put_nowait(params)

    async def schedule_punching_with_delay(self, pipe_id, n=2):
        await asyncio.sleep(n)

        # Ready to do the punching process.
        self.add_punch_meeting([
            pipe_id,
        ])

    async def load_signal_pipe(self, offset):
        server = MQTT_SERVERS[offset]

        # Lookup IP and port of MQTT server.
        try:
            dest_tup = (
                server["host"],
                server["port"],
            )
        except:
            # Fallback to fixed IPs if host res fails.
            ip = server[IP4] or server[IP6]
            dest_tup = (ip, server["port"])

        signal_pipe = SignalMock(
            peer_id=to_s(self.node_id),
            f_proto=self.signal_protocol,
            mqtt_server=dest_tup
        )

        try:
            await signal_pipe.start()
            self.signal_pipes[offset] = signal_pipe
            return signal_pipe
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
    async def load_signal_pipes(self, node_id):
        # Offsets for MQTT servers.
        offsets = [n for n in range(0, len(MQTT_SERVERS))]
        shuffled = []

        """
        The server offsets are put in a deterministic order
        based on the node_id. This is so restarting a server
        lands on the same signal servers and peers with the
        old address can still reach that node.
        """
        x = dhash(node_id)
        while len(offsets):
            pos = field_wrap(x, [0, len(offsets) - 1])
            index = offsets[pos]
            shuffled.append(index)
            offsets.remove(index)

        """
        Load the signal pipes based on the limit.
        """
        success_no = 0
        for index in shuffled:
            ret = await self.load_signal_pipe(index)
            if ret is not None:
                success_no += 1

            if success_no >= self.conf["sig_pipe_no"]:
                return
    
    def find_signal_pipe(self, addr):
        our_offsets = list(self.signal_pipes)
        for offset in addr["signal"]:
            if offset in our_offsets:
                return self.signal_pipes[offset]

        return None

    async def listen_on_ifs(self):
        # Multi-iface connection facilitation.
        for nic in self.ifs:
            # Listen on first route for AFs.
            outs = await self.listen_local(
                TCP,
                self.listen_port,
                nic
            )

            # Add global address listener.
            if IP6 in nic.supported():
                route = await nic.route(IP6).bind(
                    port=self.listen_port
                )

                out = await self.add_listener(TCP, route)
                outs.append(out)

    def pipe_future(self, pipe_id):
        if pipe_id not in self.pipes:
            self.pipes[pipe_id] = asyncio.Future()

        return pipe_id

    def pipe_ready(self, pipe_id, pipe):
        if pipe_id not in self.pipes:
            log(f"pipe ready for non existing pipe {pipe_id}!")
            return
        
        if not self.pipes[pipe_id].done():
            self.pipes[pipe_id].set_result(pipe)
        
        return pipe
    
    # Make already loaded sig pipes first to try.
    def prioritize_sig_pipe_overlap(self, offsets):
        overlap = []
        non_overlap = []
        for offset in offsets:
            if offset in self.signal_pipes:
                overlap.append(offset)
            else:
                non_overlap.append(offset)

        return overlap + non_overlap

    async def await_peer_con(self, msg, vk=None, m=0, relay_no=2):
        # Encrypt the message if the public key is known.
        buf = b"\0" + msg.pack()
        dest_node_id = msg.routing.dest["node_id"]

        # Loaded from PNP root server.
        if dest_node_id in self.auth:
            vk = self.auth[dest_node_id]["vk"]

        # Else loaded from a MSN.
        if vk is not None:
            assert(isinstance(vk, bytes))
            buf = b"\1" + encrypt(
                vk,
                msg.pack(),
            )

        # UTF-8 messes up binary data in MQTT.
        buf = to_h(buf)

        # Try not to load a new signal pipe if
        # one already exists for the dest.
        dest = msg.routing.dest
        offsets = dest["signal"]
        offsets = self.prioritize_sig_pipe_overlap(offsets)

        # Try signal pipes in order.
        # If connect fails try another.
        count = 0
        for i in range(0, len(offsets)):
            """
            The start location within the offset list
            depends on the technique no in the p2p_pipe
            so that a different start server can be used
            per method to skip failing on the same
            server every time. Adds more resilience.
            """
            offset = offsets[(i + (m - 1)) % len(offsets)]

            # Use existing sig pipe.
            if offset in self.signal_pipes:
                sig_pipe = self.signal_pipes[offset]

            # Or load new server offset.
            if offset not in self.signal_pipes:
                sig_pipe = await async_wrap_errors(
                    self.load_signal_pipe(offset)
                )

            # Failed.
            if sig_pipe is None:
                continue

            # Send message.
            sent = await async_wrap_errors(
                sig_pipe.send_msg(
                    buf,
                    to_s(dest["node_id"])
                )
            )

            # Otherwise try next signal pipe.
            if sent:
                count += 1

            # Relay limit reached.
            if count >= relay_no:
                return
            
        # TODO: no paths to host.
        # Need fallback plan here.

    async def sig_msg_dispatcher(self):
        try:
            x = await self.sig_msg_queue.get()
            if x is None:
                return
            else:
                msg, vk, m = x
            
            await async_wrap_errors(
                self.await_peer_con(
                    msg,
                    vk,
                    m,
                )
            )

            self.sig_msg_dispatcher_task = create_task(
                self.sig_msg_dispatcher()
            )
        except RuntimeError:
            log_exception()
            return
        
    def start_sig_msg_dispatcher(self):
        # Route messages to destination.
        if self.sig_msg_dispatcher_task is None:
            self.sig_msg_dispatcher_task = create_task(
                self.sig_msg_dispatcher()
            )

    async def close_idle_pipes(self):
        """
        As the number of free processes in the process pool
        decreases and the pool approaches full the need to
        check for idle connections to free up processes becomes
        more urgent. The math bellow allocates an interval to use
        for the idle count down based on urgency (remaining
        processes) in reference to a min and max idle interval.)
        """
        floor_check = 300
        ceil_check = 7200
        alloc_pcent = self.active_punchers / self.max_punchers
        num_space = ceil_check - floor_check
        rel_placement = num_space * alloc_pcent
        abs_placement = ceil_check - rel_placement
        cur_time = time.time()
        while 1:
            # Check the list of oldest monitored pipes to least.
            close_list = []
            for pipe in self.last_recv_queue:
                # Get last recv time.
                last_recv = self.last_recv_table[pipe.sock]
                elapsed = cur_time - last_recv

                # No time passed.
                if elapsed <= 0:
                    break
                
                # Sorted by time so >= this aren't expired.
                if elapsed < abs_placement:
                    break

                # Record pipe to close.
                if elapsed >= abs_placement:
                    close_list.append(pipe)

            # Don't change the prev list we're iterating.
            # Close these idle connections.
            for pipe in close_list:
                self.last_recv_queue.remove(pipe)
                del self.last_recv_table[pipe.sock]
                await pipe.close()

            # Don't tie up event loop
            await asyncio.sleep(5)

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
        async def forward_server(server):
            ret = await server.route.forward(port=port)
            msg = f"<upnp> Forwarded {server.route.ext()}:{port}"
            msg += f" on {server.route.interface.name}"
            if ret:
                Log.log_p2p(msg, self.node_id[:8])

        # Loop over all listen pipes for this node.
        await self.for_server_in_self(forward_server)

    def p2p_pipe(self, dest_bytes):
        return P2PPipe(dest_bytes, self)

    # Shutdown the node server and do cleanup.
    async def close(self):
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
        """
        Node close will throw: 
        Exception ignored in: <function BaseEventLoop.__del__
        with socket error -1

        So you need to make sure to wrap coroutines for exceptions.
        
        """

        # Stop node server.
        await super().close()
        await asyncio.sleep(.25)
        
        