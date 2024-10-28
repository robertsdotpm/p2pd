"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.
"""

from .utils import *
from .p2p_defs import *
from .p2p_utils import CON_ID_MSG
from .ecies import encrypt, decrypt

SIG_PROTO = {
    SIG_CON: [ConMsg, P2P_DIRECT, 5],
    SIG_TCP_PUNCH: [TCPPunchMsg, P2P_PUNCH, 20],
    SIG_TURN: [TURNMsg, P2P_RELAY, 10],
    SIG_GET_ADDR: [GetAddr, 0, 5],
    SIG_RETURN_ADDR: [ReturnAddr, 0, 6],
    #SIG_ADDR: [AddrMsg, 0, 5],
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

        # Get address.
        if isinstance(msg, GetAddr):
            reply = ReturnAddr({
                "meta": {
                    "ttl": int(self.node.sys_clock.time()) + 5,
                    "pipe_id": msg.meta.pipe_id,
                    "src_buf": self.node.addr_bytes,
                },
                "routing": {
                    "dest_buf": msg.meta.src_buf,
                },
            })

            # Our key for an encrypted reply.
            reply.cipher.vk = to_h(self.node.vk.to_string("compressed"))

            pp.route_msg(reply, reply=msg)
            return

        # Connect to chosen address.
        task = create_task(
            pp.connect(
                strategies=[strategy],
                reply=msg,
                conf=conf,
            )
        )
        self.node.tasks.append(task)
    
    # Receive a protocol message and validate it.
    async def proto(self, h):
        buf = h_to_b(h)
        is_enc = buf[0]
        if is_enc:
            try:
                buf = decrypt(
                    self.node.sk,
                    buf[1:]
                )
                self.node.log("net", f"Recv decrypted {buf}")
            except:
                self.node.log("net", f"Failed to decrypt {h}")
                log_exception()
        else:
            buf = buf[1:]

        if buf[0] not in SIG_PROTO:
            self.node.log("net", f"Recv unknown sig msg {h}")
            return

        try:
            # Unpack message into fields.
            msg_info = SIG_PROTO[buf[0]]
            msg_class = msg_info[0]
            msg = msg_class.unpack(buf[1:])

            # Is this message meant for us?
            dest = msg.routing.dest
            node_id = to_s(self.node.p2p_addr["node_id"])
            if to_s(dest["node_id"]) != node_id:
                m = f"Got msg for wrong node_id "
                m += f"{dest['node_id']}"
                self.node.log("net", m)
                return
            
            # Old message?
            pipe_id = msg.meta.pipe_id
            if pipe_id in self.seen:
                self.node.log("net", f"p id {pipe_id} already seen")
                return
            else:
                self.seen[pipe_id] = time.time()

            # Check TTL.
            if int(self.node.sys_clock.time()) >= msg.meta.ttl:
                self.node.log("net", f"msg ttl reached {buf}")
                return
            
            # Updating routing dest with current addr.
            assert(msg is not None)
            msg.set_cur_addr(self.node.addr_bytes)
            msg.routing.load_if_extra(self.node)

            """
            Only the dest and author knows the original msg
            so if they reply with the right pipe_id and vkc
            there's no need to check vkc.
            """
            if isinstance(msg, ReturnAddr):
                if pipe_id not in self.node.addr_futures:
                    log("pipe id not in addr futures")
                    return
                
                self.node.addr_futures[pipe_id].set_result(msg)
                return
            
            # Toggle local and remote address support.
            conf = dict_child({
                "addr_types": msg.meta.addr_types,
            }, self.conf)

            # Take action based on message.
            return await self.handle_msg(msg_info, msg, conf)
        except:
            self.node.log("net", f"unknown handling {buf}")
            log_exception()
    
async def node_protocol(self, msg, client_tup, pipe):
    log(f"> node proto = {msg}, {client_tup}")

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
            log(f"pipe = '{pipe_id}' not in pipe events. saving.")
            self.pipe_ready(pipe_id, pipe)


