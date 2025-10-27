from ..utility.utils import *
from ..node.node_addr import *
from ..node.nickname import *
from .signaling.signaling_msgs import GetAddr

"""
A nodes PNS address gets resolved to address bytes.
Then because the node may have moved or changed,
an MQTT signaling message asks that node for its most
recent address bytes.
"""
async def get_updated_addr_bytes(node, dest_addr):
    addr_bytes = None
    if pnp_name_has_tld(dest_addr):
        msg = fstr("Translating '{0}'", (dest_addr,))
        Log.log_p2p(msg, node.node_id[:8])
        name = dest_addr
        pkt = await node.nick_client.fetch(dest_addr)
        print("nick pkt vkc = ", pkt.vkc)
        assert(pkt.vkc)
        addr_bytes = pkt.value
        assert(pkt.vkc)
        print("got addr bytes:", dest_addr)

        msg = fstr("Resolved '{0}' = '{1}'", (name, dest_addr,))
        Log.log_p2p(msg, node.node_id[:8])

        # Parse address bytes to a dict.
        addr = parse_peer_addr(addr_bytes)
        print(addr)

        # Authorize this node for replies.
        assert(isinstance(pkt.vkc, bytes))
        node.auth[addr["node_id"]] = {
            "vk": pkt.vkc,
            "sk": None,
        }

        print("auth table:", node.auth)

        # Reply must match this ID with this sender key.
        pipe_id = to_s(rand_plain(10))
        node.addr_futures[pipe_id] = asyncio.Future()

        # Request most recent address from peer using MQTT.
        msg = GetAddr({
            "meta": {
                "ttl": int(node.sys_clock.time()) + 5,
                "pipe_id": pipe_id,
                "src_buf": node.addr_bytes,
            },
            "routing": {
                "dest_buf": addr_bytes,
            },
        })

        # Our key for an encrypted reply.
        msg.cipher.vk = to_h(node.vk.to_string("compressed"))

        # Their key as loaded from PNS.
        assert(pkt.vkc)
        node.sig_msg_queue.put_nowait([msg, pkt.vkc, 0])

        # Wait for an updated address.
        reply = None
        try:
            # Get a return addr reply.
            reply = await asyncio.wait_for(
                node.addr_futures[pipe_id],
                5
            )

            # Use the src addr directly.
            print("Got updated addr.", reply.meta.src_buf)
            addr_bytes = reply.meta.src_buf
        except asyncio.TimeoutError:
            print("addr requ timed out")
            return addr_bytes

    else:
        raise Exception("dest addr not a pnp name")

    return addr_bytes
