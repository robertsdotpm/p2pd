"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.
"""

from ..utility.utils import *
from ..traversal.signaling.signaling_msgs import *
from .node_defs import CON_ID_MSG
from ..vendor.ecies import encrypt, decrypt

async def node_protocol(self, msg, client_tup, pipe):
    log(fstr("> node proto = {0}, {1}", (msg, client_tup,)))

    # Simplified echo proto.
    if msg == b"long_p2pd_test_string_abcd123":
        await pipe.send(b"p2pd test string\r\n\r\n", client_tup)
        return
    
    # Execute basic services of the node protocol.
    parts = msg.split(b" ")
    cmd = parts[0]

    # This connection was in regards to a request.
    if cmd == CON_ID_MSG:
        # Invalid format.
        if len(parts) != 2:
            log("ID: Invalid parts len.")
            return 1

        # If no ones expecting this connection its a reverse connect.
        pipe_id = to_s(parts[1])
        if pipe_id not in self.pipes:
            self.pipe_future(pipe_id)

        # Tell waiter about this pipe.
        if pipe_id in self.pipes:
            log(fstr("pipe = '{0}' not in pipe events. saving.", (pipe_id,)))
            self.pipe_ready(pipe_id, pipe)


