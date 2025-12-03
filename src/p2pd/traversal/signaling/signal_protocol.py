"""
Using offsets for servers is a bad idea as server
lists need to be updated. Use short, unique IDs or
index by host name even if its longer.

-----

multiple useless layers of abstraction:
    signal protocol just wraps proto handlers.proto

handle_msg:
    designed to pass a reply to a strategy
    probably uselesssly abstract and terrible naming

"sigprotohandler.proto":
    figure out type of message
    check if its meant for us
    filter already seen
    filter old msg
    update dest routing info (our own addr)
    check if reply for returnaddr
    pass to handle_msg
"""

from ...utility.utils import *
from ...vendor.ecies import encrypt, decrypt
from .signal_msgs import *
from ..tunnel import Tunnel



# Used by the MQTT clients.
async def signal_protocol(self, msg, signal_pipe):
    #print("Signal_protocol msg:", msg)
    out = await async_wrap_errors(
        self.sig_proto_handlers.proto(msg)
    )

    #print(out)

    if isinstance(out, SigMsg):
        await signal_pipe.send_msg(
            out,
            out.routing.dest["node_id"]
        )

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

        tunnel = Tunnel(msg.meta.src_buf, self.node)

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

            # TODO: still using dubious route message func.
            tunnel.route_msg(reply, reply=msg)
            return

        # Connect to chosen address.
        task = create_task(
            tunnel.connect(
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
                self.node.log("net", fstr("Recv decrypted {0}", (buf,)))
            except Exception:
                self.node.log("net", fstr("Failed to decrypt {0}", (h,)))
                log_exception()
        else:
            buf = buf[1:]

        if buf[0] not in SIG_PROTO:
            self.node.log("net", fstr("Recv unknown sig msg {0}", (h,)))
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
                m = fstr("Got msg for wrong node_id ")
                m += fstr("{0}", (dest['node_id'],))
                self.node.log("net", m)
                return
            
            # Old message?
            pipe_id = msg.meta.pipe_id
            if pipe_id in self.seen:
                self.node.log("net", fstr("p id {0} already seen", (pipe_id,)))
                return
            else:
                self.seen[pipe_id] = time.time()

            # Check TTL.
            if int(self.node.sys_clock.time()) >= msg.meta.ttl:
                self.node.log("net", fstr("msg ttl reached {0}", (buf,)))
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
        except Exception:
            self.node.log("net", fstr("unknown handling {0}", (buf,)))
            log_exception()
    