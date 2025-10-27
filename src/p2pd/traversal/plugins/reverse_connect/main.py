from ....traversal.signaling.signaling_msgs import ConMsg

async def reverse_connect(self, af, pipe_id, src_info, dest_info, iface, addr_type, reply=None):
    msg = ConMsg({
        "meta": {
            "ttl": int(self.node.sys_clock.time()) + 10,
            "af": af,
            "pipe_id": pipe_id,
            "src_buf": self.src_bytes,
            "src_index": src_info["if_index"],
            "addr_types": [addr_type],
        },
        "routing": {
            "af": af,
            "dest_buf": self.dest_bytes,
            "dest_index": dest_info["if_index"],
        },
    })

    #self.route_msg(msg, m=0)
    dest_node_id = self.dest["node_id"]
    dest_pkc = self.node.auth[dest_node_id]["vk"]
    self.node.sig_msg_queue.put_nowait([msg, dest_pkc , 1])
    return await self.node.pipes[pipe_id]