"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.

- we're not always interested in crafting an entirely
new package e.g. the turn response only switches the
src and dest, and changes the payload
it might make sense to take this into account

TODO: Add node.msg_cb to pipes started part of 
these methods.
"""


from .utils import *
from .settings import *
from .address import *
from .p2p_addr import *
from .p2p_defs import *


class SigProtoHandlers():
    def __init__(self, node, conf=P2P_PIPE_CONF):
        self.node = node
        self.seen = {}
        self.conf = conf

    async def handle_con_msg(self, msg, conf):
        # Connect to chosen address.
        pp = self.node.p2p_pipe(
            msg.meta.src_buf,
            reply=msg,
            conf=conf,
        )

        # Connect to chosen address.
        await asyncio.wait_for(
            pp.connect(strategies=[P2P_DIRECT]),
            5
        )
    
    """
    Supports both receiving initial mappings and
    receiving updated mappings by checking state.
    The same message type is used for both which
    avoids code duplication and keeps it simple.
    """
    async def handle_punch_msg(self, msg, conf):
        print(msg.pack())
        pp = self.node.p2p_pipe(
            msg.meta.src_buf,
            reply=msg,
            conf=conf,
        )

        # Connect to chosen address.
        pipe = await asyncio.wait_for(
            pp.connect(strategies=[P2P_PUNCH]),
            10
        )

        print("handle punch pipe = ")
        print(pipe)
        return

    async def handle_turn_msg(self, msg, conf):
        print("in handle turn msg")
        pp = self.node.p2p_pipe(
            msg.meta.src_buf,
            reply=msg,
            conf=conf,
        )

        # Connect to chosen address.
        msg = await asyncio.wait_for(
            pp.connect(strategies=[P2P_RELAY]),
            10
        )

        return msg

    async def proto(self, buf):
        p_node = self.node.addr_bytes
        p_addr = self.node.p2p_addr
        node_id = to_s(p_addr["node_id"])
        handler = None
        if buf[0] == SIG_CON:
            msg = ConMsg.unpack(buf[1:])
            print("got sig p2p dir")
            print(msg)
            handler = self.handle_con_msg
        
        if buf[0] == SIG_TCP_PUNCH:
            print("got punch msg")
            msg = TCPPunchMsg.unpack(buf[1:])
            handler = self.handle_punch_msg

        if buf[0] == SIG_TURN:
            print("Got turn msg")
            msg = TURNMsg.unpack(buf[1:])
            handler = self.handle_turn_msg

        if handler is None:
            return

        dest = msg.routing.dest
        if to_s(dest["node_id"]) != node_id:
            print(f"Received message not intended for us. {dest['node_id']} {node_id}")
            return
        
        # Reject already processed.
        if msg.meta.pipe_id in self.seen:
            print("in seen")
            return
        else:
            self.seen[msg.meta.pipe_id] = 1

        conf = dict_child({
            "addr_types": msg.meta.addr_types
        }, self.conf)

        
        # Updating routing dest with current addr.
        assert(msg is not None)
        msg.set_cur_addr(p_node)
        msg.routing.load_if_extra(self.node)
        
        return await handler(msg, conf)
    
async def node_protocol(self, msg, client_tup, pipe):
    log(f"> node proto = {msg}, {client_tup}")

    # Execute any custom msg handlers on the msg.
    run_handlers(pipe, self.msg_cbs, client_tup, msg)

    # Execute basic services of the node protocol.
    parts = msg.split(b" ")
    cmd = parts[0]

    # Basic echo server used for testing networking.
    if cmd == b"ECHO":
        if len(msg) > 5:
            await pipe.send(memoryview(msg)[5:], client_tup)

        return

    # This connection was in regards to a request.
    if cmd == b"ID":
        # Invalid format.
        if len(parts) != 2:
            log("ID: Invalid parts len.")
            return 1

        # If no ones expecting this connection its a reverse connect.
        pipe_id = to_s(parts[1])
        if pipe_id not in self.pipes:
            pass
            self.pipe_future(self.pipe_id)


        if pipe_id in self.pipes:
            log(f"pipe = '{pipe_id}' not in pipe events. saving.")
            self.pipe_ready(pipe_id, pipe)


"""
Index cons by pipe_id -> future and then
set the future when the con is made.
Then you can await any pipe even if its
made by a more complex process (like punching.)

Maybe a pipe_open improvement.

"""


if __name__ == '__main__':
    pass
    #async_test(test_proto_rewrite5)

"""
    Signal proto:
        - one big func
        - a case for every 'cmd' ...
        - i/o bound (does io in the func)
        - no checks for bad addrs
        - 

    
"""

