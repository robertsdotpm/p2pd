"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.
"""

from .utils import *
from .p2p_defs import *
from .ecies import encrypt, decrypt

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

    # Take an action based on a protocol message.
    async def handle_msg(self, info, msg, conf):
        # Unpack info.
        _, strategy, timeout = info

        # Connect to chosen address.
        pp = self.node.p2p_pipe(
            msg.meta.src_buf
        )

        # Connect to chosen address.
        return await asyncio.wait_for(
            pp.connect(
                strategies=[strategy],
                reply=msg,
                conf=conf,
            ),
            timeout
        )
    
    # Receive a protocol message and validate it.
    async def proto(self, buf):
        buf = h_to_b(buf)
        is_enc = buf[0]
        if is_enc:
            print("got encrypted msg")
            print(buf)
            buf = decrypt(
                self.node.sk.to_string(),
                buf[1:]
            )
        else:
            buf = buf[1:]

        if buf[0] not in SIG_PROTO:
            print(f"proto got unsupported msg {buf[0]}")
            return

        print(f"sig msg got {buf}")
        
        # Unpack message into fields.
        msg_info = SIG_PROTO[buf[0]]
        msg_class = msg_info[0]
        msg = msg_class.unpack(buf[1:])

        # Is this message meant for us?
        dest = msg.routing.dest
        node_id = to_s(self.node.p2p_addr["node_id"])
        if to_s(dest["node_id"]) != node_id:
            print(f"Received message not intended for us. {dest['node_id']} {node_id}")
            return
        
        # Old message?
        if msg.meta.pipe_id in self.seen:
            return
        else:
            self.seen[msg.meta.pipe_id] = time.time()
        
        # Allow encryption.
        if is_enc:
            src_node_id = msg.meta.src["node_id"]
            if src_node_id not in self.node.auth:
                assert(isinstance(msg.cipher.vk, bytes))
                self.node.auth[src_node_id] = {
                    "vk": msg.cipher.vk
                }
        
        # Updating routing dest with current addr.
        print(msg is not None)
        assert(msg is not None)
        msg.set_cur_addr(self.node.addr_bytes)
        msg.routing.load_if_extra(self.node)
        
        # Toggle local and remote address support.
        conf = dict_child({
            "addr_types": msg.meta.addr_types
        }, self.conf)

        # Take action based on message.
        print("calling handle msg")
        return await self.handle_msg(msg_info, msg, conf)
    
async def node_protocol(self, msg, client_tup, pipe):
    log(f"> node proto = {msg}, {client_tup}")

    # Execute any custom msg handlers on the msg.
    run_handlers(pipe, self.msg_cbs, client_tup, msg)

    # Execute basic services of the node protocol.
    parts = msg.split(b" ")
    cmd = parts[0]

    print(msg)
    print(client_tup)


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
            self.pipe_future(pipe_id)
        #else:
        #    # Invalid handshake.
        #    await pipe.close()


        if pipe_id in self.pipes:
            log(f"pipe = '{pipe_id}' not in pipe events. saving.")
            self.pipe_ready(pipe_id, pipe)


