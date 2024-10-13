"""
FIN and RST on close:

Something important to note about TCP hole punching: suppose your NAT type is one that reuses mappings under certain conditions. You go ahead and use STUN to setup the mapping and then retrieve what it is. At this point if you were to go ahead and close() the socket used for the STUN transactions it would send out a 'FIN' packet. 

Now, if the router saw that FIN it may decide to close the port mapping. We would hope that multiple outbound connections with the same local tuple to different destinations would mean that a single FIN wouldn't cause the NAT to disregard other packets. But in any case the STUN connection ought to stay open at least until the TCP punching has been completed.

Synchronicity:

TCP hole punching between two peers heavily depends on synchronized actions.
If a peer sends a SYN too early then they risk having the other side's NAT
send back an RST which will cause the connection to be closed even if the
connection later 'succeeds.' Therefore, writing one of the peers to
'start sooner' than an agreed upon time simply makes their connection unstable.
The correct way to do TCP hole punching is to start at the same time but
synchronicity between networked devices is a notoriously hard problem to solve.

Using the NTP protocol it can be off by between 1 - 50 ms which is significant
enough to matter. The algorithm tries to compensate by sampling and using
statistical methods to remove outliers. The original approach for this was
taken from the Gnuttella code (written in C) and ported to Python.

Wait times:

The protocol is meant to take up to N seconds to complete. Where N is enough
time to receive initial mappings and / or updated mappings + a buffer for
synchronized startup. There is also a limit on the whole process imposed
by the 'pipe waiter' code that waits for a pipe to be returned. If the
limit is too short then you may see connections succeed in the punching
code but then be tore down from the timeout cleanup code. I wanted to
make a note of this here. I am trying to minimize how much time is spent
sleeping so that the process is faster but I am still tweaking this.

Sharing sockets between processes:

The TCP punch module uses Python's ProcessPoolExecutor to spawn child processes
that do the punching operations. Using this design has several benefits. It
means that the timing between peers is slightly more accurate as the main process
is not interrupting the connection code. In reality though: the operating system
still controls scheduling of processes (without using special code to pin the
processes to certain cores.)

Another benefit is that parts of the code which are very 'busy' such as the local
punching algorithm (which essentially just spams connections as much as it can)
will not impact the performance of the main application. There is a consequence
to this design though. If a process exits then presumably the socket descriptors
opened from the process will become unusable. Fortunately, Python's process pool
spins up a list of processes (by default set to the core number) and reuses them.
That means that the sockets should remain valid through the software's lifetime.

Event loops:

On Linux, Mac OS X, BSD... The default event loop is the selector event loop.
On Windows the default event loop is the proactor event loop. When it comes
to running commands and making 'pipes' to processes you need to use the
proactor event loop on Windows. But for TCP hole punching to work the
selector event loop is the only one that seems to make the code work.

When running async code for the first time in an 'executor' / new process
it will need to create a new event loop. Normally this would have quite
a delay. In order to make async code run fast I pre-initialize all executors
with a call to create an event loop. So when async code is run in them
there is no startup penalty. This is important for timing-based code.

Testing:

When it comes to testing punching on the same machine it is 
sometimes necessary to run the punching code in separate processes (with their
own event loops.) Otherwise, they will interfere with each other and the
syns won't cross in time. Ideally each process should be running on its
own core with a high priority. But this is hard to guarantee in practice.

Edge-case: making another connection to the same STUN server, from the same local endpoint due to another TCP punch occurring.

Notes:

- It makes sense for the combination of the worst NAT + delta type
to go first since it means the better NAT is put in the position
of assuming receipt of their initial mappings which it can then
try to use for its own external mappings without the need to
successfully return back updated mappings. Making only one initial
message necessary to do the punching. But for now -- this is not
done. If some kind of reverse start logic is needed then it
would itself require another message. So maybe not worth the cost.
"""

import asyncio
from .nat_predict import *
from .tcp_punch_utils import *
from .clock_skew import *

class TCPPuncher():
    def __init__(self, af, src_info, dest_info, stuns, sys_clock, nic, same_machine=False):
        # Save input params.
        self.af = af
        self.src_info = src_info
        self.dest_info = dest_info
        self.stuns = stuns
        self.sys_clock = sys_clock
        self.interface = nic
        self.same_machine = same_machine

        # Short hands.
        self.set_punch_mode()
        self.side = self.state = None
        self.pipe_id = self.node = None
        self.pipe = None
        self.start_time = Dec(0)
        self.recv_mappings = []
        self.send_mappings = []
        self.preloaded_mappings = []
        self.listen_pipe = None
        self.ping_pong_task = None
        self.active_punchers = 0

    def get_ntp_meet_time(self):
        return self.sys_clock.time() + Dec(NTP_MEET_STEP)
    
    async def proto(self, recv_mappings=None, start_time=None):
        # Change protocol state transition.
        self.state, self.side = tcp_puncher_states(
            recv_mappings,
            self.state,
        )

        # Covers exchanging and receiving mappings.
        # These steps are required for success.
        fetch_states  = [INITIATED_PREDICTIONS]
        fetch_states += [RECEIVED_PREDICTIONS]
        if self.state in fetch_states:
            self.send_mappings, self.preloaded_mappings = \
                await nat_prediction(
                    self.punch_mode,
                    self.src_info["nat"],
                    self.dest_info["nat"],
                    self.stuns,
                    recv_mappings=recv_mappings,
                )

            # Ii receive mapping isn't set use templates.
            self.recv_mappings = \
                recv_mappings or copy.deepcopy(
                    self.send_mappings
                )
            
            # Patch mappings for self punch.
            # This forces different ports to be used.
            if self.side == INITIATOR:
                self_punch_patch(
                    self.punch_mode,
                    self.recv_mappings
                )
            
            # Set meeting start time.
            arrange_time = self.get_ntp_meet_time()
            self.start_time = \
                start_time or arrange_time

            # Only things needed for protocol.
            return self.send_mappings, self.start_time
                
        # Update the mapping to match needed reply ports.
        # Optional step but improves success chance.
        if self.state == UPDATED_PREDICTIONS:
            # More updated list of their NAT predictions.
            self.recv_mappings = recv_mappings

            # Adjust our local bind ports if they need a specific
            # reply port to accept a connection.
            update_for_reply_ports(
                self.punch_mode,
                self.src_info["nat"],
                self.dest_info["nat"],
                self.preloaded_mappings,
                self.recv_mappings,
                self.send_mappings,
            )

            return 1
        
    async def setup_punching_process(self):
        # Listen server that process will connect back to.
        # References are saved to avoid garbage collection.
        route = await self.interface.route(self.af).bind()
        self.listen_pipe = await pipe_open(
            TCP,
            dest=None,
            route=route,
            msg_cb=self.node.msg_cb,
        )
        
        # Might not be necessary since the get addr infos does this.
        """
        interface = await select_if_by_dest(
            self.af,
            self.dest_info["ip"],
            self.interface
        )
        """
        interface = self.interface

        # Passed on to a new process.
        listen_tup = self.listen_pipe.sock.getsockname()[:2]
        args = (
            listen_tup,
            self.to_dict(),
            interface,
            self.node.node_id[:8]
        )

        try:
            # Schedule TCP punching in process pool executor.
            loop = asyncio.get_event_loop()
            puncher_future = loop.run_in_executor(
                self.pp_executor,
                proc_do_punching,
                args
            )
            
            # Check every 100 ms for 5 seconds.
            while 1:
                try:
                    # Check if reverse connect server has a client yet.
                    if len(self.listen_pipe.tcp_clients):
                        # Reverse connect from punching process to
                        # server in the main thread.
                        self.pipe = self.listen_pipe.tcp_clients[0]

                        # Patch close to send close message.
                        pipe_close = self.pipe.close
                        async def close_patch():
                            await self.pipe.send(PUNCH_END)
                            await pipe_close()
                        self.pipe.close = close_patch

                        # Indicate hole made to waiter.
                        self.node.pipe_ready(self.pipe_id, self.pipe)
                        return self.pipe
                except:
                    log_exception()
                
                # Check every 100 ms.
                await asyncio.sleep(0.1)

                # Puncher ended.
                if puncher_future.done():
                    self.active_punchers = max(
                        0,
                        self.active_punchers - 1
                    )

                    return
        except:
            log_exception()

    def set_punch_mode(self):
        self.punch_mode = get_punch_mode(
            self.af,
            str(self.dest_info["ip"]),
            self.same_machine
        )

    def setup_multiproc(self, pp_executor):
        # Process pools are disabled.
        if pp_executor is None:
            self.pp_executor = None
            return
            
        self.pp_executor = pp_executor

    def set_parent(self, pipe_id, node):
        self.pipe_id = pipe_id
        self.node = node

    def to_dict(self):
        return puncher_to_dict(self)
    
    @staticmethod
    def from_dict(d):
        return puncher_from_dict(d, TCPPuncher)
    
    async def close(self):
        if self.pipe is not None:
            await self.pipe.close()

        if self.listen_pipe is not None:
            await self.listen_pipe.close()

# Started in a new process.
def proc_do_punching(args):
    try:


        """
        On Windows it seems like using the default 'proactor event loop'
        prevents the TCP hole punching code from working. It seems that
        manually setting the event loop to use SelectorEventLoop
        fixes the issue. However, this may mean breaking some of
        my command execution code on Windows -- test this.
        """
        asyncio.set_event_loop_policy(SelectorEventPolicy())

        # Build a puncher from a dictionary.
        reverse_tup = args[0]
        d = args[1]
        interface = args[2]
        node_id = args[3]
        puncher = TCPPuncher.from_dict(d)

        # Execute the punching in a new event loop.
        loop = asyncio.get_event_loop()
        f = create_task(
            async_wrap_errors(
                do_punching_wrapper(
                    puncher.af,
                    puncher.dest_info["ip"],
                    puncher.send_mappings,
                    puncher.recv_mappings,
                    puncher.sys_clock.time(),
                    puncher.start_time,
                    puncher.punch_mode,
                    interface,
                    reverse_tup,
                    node_id
                )
            ),
            loop=loop
        )

        # The moment the function is done save its result to the queue.
        # The queue is sharable and works with basic types.
        #f.add_done_callback(lambda t: q.put(t.result()))
        return loop.run_until_complete(f)
    except:
        log_exception()

