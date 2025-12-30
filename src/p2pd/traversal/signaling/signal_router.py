from aionetiface import *
from .signal_msgs import *
from .signal_utils import *

async def send_msg_over_mqtt(router, msg, relay_limit=2):
    # Else loaded from a MSN.
    buf = sig_msg_to_buf(msg)

    # Try not to load a new signal pipe if
    # one already exists for the dest.
    dest = msg.routing.dest
    offsets = dest["signal"]
    offsets = prioritize_sig_pipe_overlap(router, offsets)

    # Try signal pipes in order.
    # If connect fails try another.
    relay_count = 0
    for i in range(0, len(offsets)):
        # Get index referencing an MQTT server.
        offset = offsets[i]

        # Use existing sig pipe.
        if offset in router.signal_pipes:
            sig_pipe = router.signal_pipes[offset]

        # Or load new server offset.
        if offset not in router.signal_pipes:
            sig_pipe = await async_wrap_errors(
                load_signal_pipe(
                    router.node_id,
                    msg.routing.af,
                    offset,
                    MQTT_SERVERS,
                    router.msg_cb
                )
            )

            # Record it if success.
            if sig_pipe:
                router.signal_pipes[offset] = sig_pipe

        # Skip invalid sig pipes.
        if not sig_pipe:
            continue

        # Send message.
        print("send to ", dest["node_id"], " ", offset)
        await async_wrap_errors(
            sig_pipe.send_msg(
                buf,
                to_s(dest["node_id"])
            )
        )

        """
        Relay message across a minimum no of MQTT servers
        to help ensure message is received.
        """
        relay_count += 1
        if relay_count >= relay_limit:
            break
        
    # TODO: no paths to host.
    # Need fallback plan here.

class SignalRouter():
    def __init__(self, f_time, node_id, addr_bytes, sk):
        self.f_time = f_time
        self.node_id = to_s(node_id)
        self.addr_bytes = addr_bytes
        self.sk = sk
        self.vk = sk.verifying_key.to_string("compressed")
        self.seen = {}
        self.tasks = []

    def set_signal_pipes(self, signal_pipes):
        self.signal_pipes = signal_pipes
        for index in self.signal_pipes:
            signal_pipe = self.signal_pipes[index]
            signal_pipe.f_proto = self.msg_cb

    def set_traversal_manager(self, traversal):
        self.traversal = traversal

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

        msg = try_unpack_msg(msg, self.sk, SIG_PROTO)
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



