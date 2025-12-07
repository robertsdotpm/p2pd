from ...utility.utils import *
from ...vendor.ecies import encrypt, decrypt
from .signal_msgs import *
from .signal_utils import prioritize_sig_pipe_overlap
from .signal_client import SignalMock

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

async def send_msg_over_mqtt(router, msg, relay_no=2):
    # Encrypt the message if the public key is known.
    buf = b"\0" + msg.pack()

    # Else loaded from a MSN.
    if msg.cipher.vk is not None:
        assert(isinstance(msg.cipher.vk, bytes))
        buf = b"\1" + encrypt(
            msg.cipher.vk,
            msg.pack(),
        )

    # UTF-8 messes up binary data in MQTT.
    buf = to_h(buf)

    # Try not to load a new signal pipe if
    # one already exists for the dest.
    dest = msg.routing.dest
    offsets = dest["signal"]
    offsets = prioritize_sig_pipe_overlap(router, offsets)

    # Try signal pipes in order.
    # If connect fails try another.
    count = 0
    for i in range(0, len(offsets)):
        offset = offsets[i]

        # Use existing sig pipe.
        if offset in router.signal_pipes:
            sig_pipe = router.signal_pipes[offset]

        # Or load new server offset.
        if offset not in router.signal_pipes:
            sig_pipe = await async_wrap_errors(
                router.load_signal_pipe(
                    msg.routing.af,
                    offset,
                    MQTT_SERVERS
                )
            )

        # Record it if success.
        if sig_pipe:
            router.signal_pipes[offset] = sig_pipe
        else:
            continue

        # Send message.
        sent = await async_wrap_errors(
            sig_pipe.send_msg(
                buf,
                to_s(dest["node_id"])
            )
        )

        # Otherwise try next signal pipe.
        if sent:
            count += 1

        # Relay limit reached.
        if count >= relay_no:
            return
        
    # TODO: no paths to host.
    # Need fallback plan here.

class SignalRouter():
    def __init__(self, f_time, node_id, addr_bytes, sk):
        self.f_time = f_time
        self.node_id = to_s(node_id)
        self.addr_bytes = addr_bytes
        self.sk = sk
        self.vk = to_h(sk.verifying_key.to_string("compressed"))
        self.seen = {}
        self.tasks = []

    def set_signal_pipes(self, signal_pipes):
        self.signal_pipes = signal_pipes

    def set_traversal_manager(self, traversal):
        self.traversal = traversal

    async def load_signal_pipe(self, af, offset, servers):
        # Lookup IP and port of MQTT server.
        server = servers[offset]
        dest_tup = (server[af], server["port"],)

        def signal_protocol_closure():
            def closure(msg, signal_pipe):
                return self.msg_cb(msg, dest_tup, signal_pipe)
        
            return closure

        """
        This function does a basic send/recv test with MQTT to help
        ensure the MQTT servers are valid.
        """
        client = await SignalMock(
            to_s(self.node_id),
            signal_protocol_closure(),
            dest_tup
        ).start()

        return client

    async def signal_msg_sender(self, msg, plugin, relay_no=2):
        msg.meta = SigMsg.Meta.from_dict({
            "ttl": int(self.f_time()) + 30,
            "pipe_id": plugin.pipe_id,
            "af": plugin.af,
            "src_buf": plugin.src_map["bytes"],
            "src_index": plugin.src_info["if_index"],
            "addr_types": [plugin.route_type]
        })

        msg.routing = SigMsg.Routing.from_dict({
            "af": plugin.af,
            "dest_buf": plugin.dest_map["bytes"],
            "dest_index": plugin.dest_info["if_index"],
        })

        # Our key for an encrypted reply.
        msg.cipher.vk = self.vk

        # Send signaling message using MQTT.
        await send_msg_over_mqtt(self, msg, relay_no)

    def msg_cb(self, msg, client_tup, pipe):
        msg = try_unpack_msg(msg)
        if to_s(msg.routing.dest["node_id"]) != self.node_id:
            raise Exception("Message not meant for us.")
        
        print("Got new signal msg = ", msg.to_dict())

        # Raise exception if this is old.
        discard_old_msg(msg, self.seen, self.f_time)

        # Updating routing dest with current addr.
        msg.set_cur_addr(self.addr_bytes)

        # loads nic and stun client from offsets.
        msg.routing.load_if_extra(self.node) 
        
        # Pass this message on to existing plugin.
        # If one doesn't exist it will be created.
        plugin = self.traversal.get_plugin(msg)
        #TODO: make this pop off older items when it fills.
        self.tasks.append(
            asyncio.create_task(
                plugin.run(reply=msg)
            )
        )



