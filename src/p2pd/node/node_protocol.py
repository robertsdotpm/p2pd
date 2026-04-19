"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.
"""

from aionetiface import *
from .node_defs import (CON_ID_MSG)

async def node_protocol(self, msg, client_tup, pipe):
    log(fstr("> node proto = {0}, {1}", (msg, client_tup,)))

    # Simplified echo proto.
    if msg == b"long_p2pd_test_string_abcd123":
        await pipe.send(b"p2pd test string\r\n\r\n", client_tup)
        return
    
    # Execute basic services of the node protocol.
    parts = msg.split(b" ")
    cmd = parts[0]

    if cmd == CON_ID_MSG:
        if len(parts) != 2:
            log("ID: Invalid parts len.")
            return 1
        
        self.pipe_ready(to_s(parts[1]), pipe)


