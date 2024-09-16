from .settings import *
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
                    assert(len(self.stun_clients[af][if_index]))

    async def punch_queue_worker(self):
        try:
            params = await self.punch_queue.get()
            if params is None:
                print("closing punch queue worker")
                return
            
            print("do punch ")
            if len(params):
                pipe_id = params[0]
                if pipe_id in self.tcp_punch_clients:
                    puncher = self.tcp_punch_clients[pipe_id]

                    
                    task = asyncio.ensure_future(
                        async_wrap_errors(
                            puncher.setup_punching_process()
                        )
                    )

                    # Avoid garbage collection for this task.
                    self.tasks.append(task)
                    
                    """
                    await async_wrap_errors(
                        puncher.setup_punching_process()
                    )
                    """


            print("punch done")

            self.punch_worker_task = asyncio.ensure_future(
                self.punch_queue_worker()
            )
        except RuntimeError:
            print("punch queue worker run time error")
            return
        except:
            log_exception()
            what_exception()
        
    def start_punch_worker(self):
        print("in start punch worker")
        self.punch_worker_task = asyncio.ensure_future(
            self.punch_queue_worker()
        )

    async def setup_punch_coordination(self, sys_clock=None):
        if sys_clock is None:
            sys_clock = await SysClock(self.ifs[0]).start()

        self.pp_executor = await get_pp_executors()
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
    async def load_signal_pipes(self):
        tasks = []
        serv_len = len(MQTT_SERVERS)
        offsets = shuffle(list(range(serv_len)))
        sig_pipe_no = min(self.conf["sig_pipe_no"] + 1, serv_len)
        for i in range(0, sig_pipe_no):
            offset = offsets[i]
            task = self.load_signal_pipe(offset)
            tasks.append(task)

        ret = await asyncio.gather(*tasks)
        ret = strip_none(ret)
        assert(len(ret))
    
    def find_signal_pipe(self, addr):
        our_offsets = list(self.signal_pipes)
        for offset in addr["signal"]:
            if offset in our_offsets:
                return self.signal_pipes[offset]

        return None

    async def listen_on_ifs(self, protos=[TCP]):
        for nic in self.ifs:
            for proto in protos:
                await self.listen_all(
                    proto,
                    self.listen_port,
                    nic
                )

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

    async def await_peer_con(self, msg, m=0, relay_no=2):
        # Encrypt the message if the public key is known.
        buf = b"\0" + msg.pack()
        dest_node_id = msg.routing.dest["node_id"]
        if dest_node_id in self.auth:
            buf = b"\1" + encrypt(
                self.auth[dest_node_id]["vk"],
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
                msg, m = x
            
            await async_wrap_errors(
                self.await_peer_con(
                    msg,
                    m,
                )
            )

            self.sig_msg_dispatcher_task = asyncio.ensure_future(
                self.sig_msg_dispatcher()
            )
        except RuntimeError:
            log_exception()
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

    async def ping_checker(self, pipe, n=10):
        while 1:
            # Wait until ping time.
            await asyncio.sleep(n)

            # Setup ping event.
            ping_id = to_s(rand_plain(10))
            self.ping_ids[ping_id] = asyncio.Event()
            msg = to_b(f"PING {ping_id}\n")
            print(f"ping to send {msg}")

            # Send ping to node.
            await pipe.send(msg, pipe.sock.getpeername())

            # Await receipt.
            try:
                await asyncio.wait_for(
                    self.ping_ids[ping_id].wait(),
                    4
                )
                print("got pong.")
            except asyncio.TimeoutError:
                print("ping timeout")
                break

        # Close pipe.
        await pipe.close()


    # Shutdown the node server and do cleanup.
    async def close(self):
        print("in close")
        
        # Make the worker thread for punching end.
        self.punch_queue.put_nowait(None)
        if self.punch_worker_task is not None:
            self.punch_worker_task.cancel()
            self.punch_worker_task = None
        print("after punch queue cancel")

        # Stop sig message dispatcher.
        self.sig_msg_queue.put_nowait(None)
        if self.sig_msg_dispatcher_task is not None:
            self.sig_msg_dispatcher_task.cancel()
            self.sig_msg_dispatcher_task = None
        print("after sig msg queue cancel")

        # Close other pipes.
        pipe_lists = [
            self.signal_pipes,
            self.tcp_punch_clients,
            self.turn_clients,
            self.pipes,
        ]

        for pipe_list in pipe_lists:
            print(pipe_list)
            for pipe in pipe_list.values():
                print(pipe)
                if pipe is None:
                    continue

                if isinstance(pipe, asyncio.Future):
                    if pipe.done():
                        pipe = pipe.result()
                    else:
                        continue
                        
                print("try pipe close")
                await pipe.close()

        # Try close the multiprocess manager.
        print("before cleanup multi proc")
        print("after cleanup multi proc")

        """
        Node close will throw: 
        Exception ignored in: <function BaseEventLoop.__del__
        with socket error -1

        So you need to make sure to wrap coroutines for exceptions.
        
        """

        # Stop node server.
        print("stop node server")
        await super().close()
        print("after stop node server")

        await asyncio.sleep(.25)
        
        