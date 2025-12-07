import asyncio
from ..traversal_utils import *

class TraversalPlugin():
    def __init__(self):
        self.result = asyncio.Future()

    def set_addrs(self, src_map, dest_map):
        self.src_map = src_map
        self.dest_map = dest_map

    def set_routing(self, af, src_info, dest_info, nic):
        self.af = af
        self.src_info = src_info
        self.dest_info = dest_info
        self.nic = nic

        # Ensure our selected NIC is what the
        # remote peer wanted to use for the technique.
        """
        if reply is not None:
            if reply.routing.dest_index != src_info["if_index"]:
                raise Exception("Invalid NIC loaded for plugin.")
        """
            
    def set_context(self, route_type, same_machine, set_bind, timeout):
        self.route_type = route_type
        self.same_machine = same_machine
        self.set_bind = set_bind
        self.timeout = timeout

        """
        Determine the best destination IP to use
        for the connectivity technique based on
        addressing and relationships between the
        two machines (deep networking specific.)
        """
        self.dest_info["ip"] = str(
            select_dest_ipr(
                self.af,
                same_machine,
                self.src_info,
                self.dest_info,
                [route_type],

                # can you make this case
                # run for all
                # try it
                set_bind,
            )
        )

        # Need a destination address.
        # Possibly a different address type will work.
        if self.dest_info["ip"] == "None":
            raise Exception("Cannot select valid dest IP")

    def set_pipe_id(self, pipe_id, pipe_future):
        self.pipe_id = pipe_id
        self.pipe_future = pipe_future

    def set_signal_msg_sender(self, signal_msg_sender):
        self.signal_msg_sender = signal_msg_sender

    async def run(self, reply=None):
        print("run parent.")