from ...utility.utils import *
from .signal_msgs import *
from .signal_utils import *
from .signal_client import SignalMock

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



