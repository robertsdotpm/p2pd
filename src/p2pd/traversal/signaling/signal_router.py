from ...utility.utils import *
from ...vendor.ecies import encrypt, decrypt
from .signal_msgs import *
from .signal_utils import prioritize_sig_pipe_overlap
from .signal_client import SignalMock

def try_unpack_msg(buf, sk):
    print("try unpack msg = ", buf)
    buf = h_to_b(buf)

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
        log("Discard already seen msg.")
        return
    else:
        seen[pipe_id] = time.time()

    # Check TTL.
    if int(f_time()) >= msg.meta.ttl:
        log("Discard old msg.")
        return
    
    return msg

async def send_msg_over_mqtt(router, msg, relay_no=2):
    # Else loaded from a MSN.
    dest_vk = msg.routing.dest["vk"]
    print("Dest vk = ", dest_vk)
    if dest_vk:
        assert(isinstance(dest_vk, bytes))
        buf = b"\1" + encrypt(
            dest_vk,
            msg.pack(),
        )
    else:
        buf = b"\0" + msg.pack()

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
        print("send to ", dest["node_id"], " ", offset)
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
        self.vk = sk.verifying_key.to_string("compressed")
        print("sig vk = ", self.vk)
        self.seen = {}
        self.tasks = []

    def set_signal_pipes(self, signal_pipes):
        self.signal_pipes = signal_pipes
        for index in self.signal_pipes:
            signal_pipe = self.signal_pipes[index]
            signal_pipe.f_proto = self.msg_cb

    def set_traversal_manager(self, traversal):
        self.traversal = traversal

    async def load_signal_pipe(self, af, offset, servers):
        print("in load signal pipe ", af, offset, servers)

        # Lookup IP and port of MQTT server.
        server = servers[offset]
        dest_tup = (server[af], server["port"],)
        """
        This function does a basic send/recv test with MQTT to help
        ensure the MQTT servers are valid.
        """
        client = await SignalMock(
            to_s(self.node_id),
            self.msg_cb,
            dest_tup
        ).start()

        print("client result = ", client)

        return client

    async def signal_msg_sender(self, msg, plugin, relay_no=2):
        msg.meta = SigMsg.Meta.from_dict({
            "ttl": int(self.f_time()) + 30,
            "pipe_id": plugin.pipe_id,
            "af": plugin.af,
            "src_buf": plugin.src_map["bytes"],
            "src_index": plugin.src_info["if_index"],
            "route_type": plugin.route_type,
            "same_machine": plugin.same_machine,
            "plugin_name": msg.meta.plugin_name,
        })

        msg.routing = SigMsg.Routing.from_dict({
            "af": plugin.af,
            "dest_buf": plugin.dest_map["bytes"],
            "dest_index": plugin.dest_info["if_index"],
        })

        # Our key for an encrypted reply.
        msg.cipher.vk = self.vk

        # Send signaling message using MQTT.
        print("in signal msg sender")
        await async_wrap_errors(
            send_msg_over_mqtt(self, msg, relay_no)
        )

        print(msg.to_dict())

    def msg_cb(self, msg, client_tup, pipe):
        print("in signal router msg_cb")

        msg = try_unpack_msg(msg, self.sk)
        if to_s(msg.routing.dest["node_id"]) != self.node_id:
            raise Exception("Message not meant for us.")
        
        print("Got new signal msg = ", msg.to_dict())

        # Raise exception if this is old.
        msg = discard_old_msg(msg, self.seen, self.f_time)
        if not msg:
            return

        # Updating routing dest with current addr.
        msg.set_cur_addr(self.addr_bytes)
        
        # Pass this message on to existing plugin.
        # If one doesn't exist it will be created.
        plugin = self.traversal.get_plugin(msg)

        #TODO: make this pop off older items when it fills.
        self.tasks.append(
            asyncio.create_task(
                async_wrap_errors(
                    plugin.run(reply=msg)
                )
            )
        )



