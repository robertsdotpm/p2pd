
from ..settings import *
from ..utility.utils import *
from ..utility.machine_id import hashed_machine_id
from ..traversal.plugins.tcp_punch.tcp_punch_client import PUNCH_CONF
from .node_utils import *
from ..traversal.tunnel import *
from ..traversal.signaling.signaling_client import *
from ..protocol.stun.stun_client import *
from ..nic.nat.nat_utils import USE_MAP_NO
from ..install import *
from ..vendor.ecies import encrypt, decrypt
from ..utility.clock_skew import SysClock
from ..traversal.signaling.signaling_protocol import signal_protocol
import asyncio
import pathlib
from ecdsa import SigningKey, SECP256k1

class P2PNodeExtra():
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
            log(fstr("pipe ready for non existing pipe {0}!", (pipe_id,)))
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
                    self.load_signal_pipe(
                        msg.routing.af,
                        offset,
                        MQTT_SERVERS
                    )
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
        print("in sig msg dispatcher")
        try:
            x = await self.sig_msg_queue.get()
            print("got sig msg q item", x)
            if x is None:
                return
            else:
                msg, vk, m = x
                if None in (msg, vk, m,):
                    log(
                        "Invalid sig msg params = " + 
                        str(msg) + 
                        str(vk) + 
                        str(m)
                    )
                print(msg, vk, m)
            
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
            print("run time error in sig msg dispatcher")
            what_exception()
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
            msg = fstr("<upnp> Forwarded {0}:{1}", (server.route.ext(), port,))
            msg += fstr(" on {0}", (server.route.interface.name,))
            if ret:
                Log.log_p2p(msg, self.node_id[:8])

        # Loop over all listen pipes for this node.
        await self.for_server_in_self(forward_server)

    def p2p_pipe(self, dest_bytes):
        return Tunnel(dest_bytes, self)

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
        
        