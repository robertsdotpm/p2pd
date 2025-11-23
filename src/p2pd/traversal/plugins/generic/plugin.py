

from ....nic.nat.nat_predict import *
from ....utility.clock_skew import *
from ....net.asyncio.event_loop import *

# stuns
class GenericPlugin():
    def __init__(self):
        # Save input params.
        self.af = self.src_info = self.dest_info = None
        self.interface = None

        # Short hands.
        self.pipe_id = self.node = None
        self.pipe = None
        self.listen_pipe = None
        self.ping_pong_task = None
        self.stun_clients = None

    def set_stun_clients(self, stun_clients):
        self.stun_clients = stun_clients

    def set_routing(self, af, src_info, dest_info, nic, same_machine=False):
        self.af = af
        self.src_info = src_info
        self.dest_info = dest_info
        self.nic = nic

    def setup_multiproc(self, pp_executor):
        # Process pools are disabled.
        if pp_executor is None:
            self.pp_executor = None
            return
            
        self.pp_executor = pp_executor

    def set_parent(self, pipe_id, node):
        self.pipe_id = pipe_id
        self.node = node
    
    async def close(self):
        if self.pipe is not None:
            await self.pipe.close()

        if self.listen_pipe is not None:
            await self.listen_pipe.close()

