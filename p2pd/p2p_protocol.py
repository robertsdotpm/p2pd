"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.
"""
from .utils import *
from .settings import *
from .address import *
from .pipe_events import *
from .p2p_defs import *

SIG_PROTO = {
    SIG_CON: [ConMsg, P2P_DIRECT, 5],
    SIG_TCP_PUNCH: [TCPPunchMsg, P2P_PUNCH, 10],
    SIG_TURN: [TURNMsg, P2P_RELAY, 10],
}

class SigProtoHandlers():
    def __init__(self, node, conf=P2P_PIPE_CONF):
        self.node = node
        self.seen = {}
        self.conf = conf

    async def unpack(self, msg_type, buf):
        # Address of the local node.
        addr = self.node.p2p_addr
        node_id = to_s(self.addr["node_id"])

        # Use the right message type to unpack the message.
        msg = SIG_PROTO[msg_type][0]
        msg.unpack(buf[1:])

        # Reject messages that don't match our  node id.
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

        # Updating routing dest with current addr.
        assert(msg is not None)
        msg.set_cur_addr(addr)
        msg.routing.load_if_extra(self.node)
        return msg

    async def handler(self, msg_type, msg):
        # Support using private and/or pub addresses.
        conf = dict_child({
            "addr_types": msg.meta.addr_types
        }, self.conf)

        # Load a P2P pipe with the reply details.
        _, strategy, timeout = SIG_PROTO[msg_type]
        pp = self.node.p2p_pipe(
            msg.meta.src_buf,
            reply=msg,
            conf=conf,
        )

        # Connect to chosen address.
        out = await asyncio.wait_for(
            pp.connect(strategies=[strategy]),
            timeout,
        )

        return out

    async def proto(self, buf):
        # Check proto message is supported.
        msg_type = buf[0]
        if msg_type not in SIG_PROTO:
            return
        
        # Unpack message using the right data structure.
        msg = await self.unpack(msg_type, buf)
        if msg is None:
            return

        # Take action based on the message.
        return await self.handler(msg_type, msg)
    
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


if __name__ == '__main__':
    pass
    #async_test(test_proto_rewrite5)

