from ...utility.utils import *
from ...vendor.ecies import encrypt, decrypt
from .signal_msgs import *

def try_unpack_msg(buf, sk):
    # Try to decrypt message if its encrypted.
    is_enc = buf[0]
    if is_enc:
        # Ensure a SK is set for decryption.
        if not sk:
            raise Exception("No sk set for decryption.")

        # Will raise if it can't decrypt.
        buf = decrypt(
            sk,
            buf[1:]
        )
        log(fstr("Recv decrypted {0}", (buf,)))
    
    # Otherwise buffer is not encrypted -- use as is.
    if not is_enc:
        buf = buf[1:]

    # Unpack message into fields.
    msg_info = SIG_PROTO[buf[0]]
    msg_class = msg_info[0]
    msg = msg_class.unpack(buf[1:])
    return msg

def discard_old_msg(msg, seen, f_time):
    # Old message?
    pipe_id = msg.meta.pipe_id
    if pipe_id in seen:
        raise Exception(fstr("p id {0} already seen", (pipe_id,)))
    else:
        seen[pipe_id] = time.time()

    # Check TTL.
    if int(f_time()) >= msg.meta.ttl:
        raise Exception(fstr("msg ttl reached {0}", (msg.meta.ttl,)))
    
    return msg

class SignalRouter():
    def __init__(self, f_time, node_id, addr_bytes, sk):
        self.f_time = f_time
        self.node_id = to_s(node_id)
        self.addr_bytes = addr_bytes
        self.sk = sk
        self.vk = to_h(sk.verifying_key.to_string("compressed"))
        self.seen = {}

    def set_traversal_manager(self, traversal):
        self.traversal = traversal

    async def f_msg_sender(self, msg, plugin):
        msg.meta = SigMsg.Meta.from_dict({
            "ttl": int(self.f_time()) + 30,
            "pipe_id": plugin.pipe_id,
            "af": plugin.af,
            "src_map": plugin.src_map,
            "src_index": plugin.src_info["if_index"],
            "addr_types": [plugin.route_type]
        })

        msg.routing = SigMsg.Routing.from_dict({
            "af": plugin.af,
            "dest_map": plugin.dest_map,
            "dest_index": plugin.dest_info["if_index"],
        })

        # Our key for an encrypted reply.
        msg.cipher.vk = self.vk

        # TODO dispatch message.

    async def msg_cb(self, msg, client_tup, pipe):
        msg = try_unpack_msg(msg)
        if to_s(msg.routing.dest["node_id"]) != self.node_id:
            raise Exception("Message not meant for us.")

        discard_old_msg(msg, self.seen, self.f_time)

        # Updating routing dest with current addr.
        msg.set_cur_addr(self.addr_bytes)
        # loads nic and stun client from offsets.
        msg.routing.load_if_extra(self.node) 

        # Pass this message on to any plugins registered for it.
        plugin = self.traversal.get_plugin(msg.meta.pipe_id)
        await plugin.run(reply=msg, f_msg_sender=self.f_msg_sender)

