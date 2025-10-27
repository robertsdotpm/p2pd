from ...utility.utils import *
from ...settings import *
from ...vendor.ecies import encrypt, decrypt
from .signaling_utils import *

async def send_sig_msg(node, msg, vk=None, m=0, relay_no=2):
    # Encrypt the message if the public key is known.
    buf = b"\0" + msg.pack()
    dest_node_id = msg.routing.dest["node_id"]

    # Loaded from PNP root server.
    if dest_node_id in node.auth:
        vk = node.auth[dest_node_id]["vk"]

    # Else loaded from a MSN.
    if vk is not None:
        assert(isinstance(vk, bytes))
        buf = b"\1" + encrypt(
            vk,
            msg.pack(),
        )

    # UTF-8 messes up binary data in MQTT.
    buf = to_h(buf)

    # Try not to load a new signal pipe if
    # one already exists for the dest.
    dest = msg.routing.dest
    offsets = dest["signal"]
    offsets = prioritize_sig_pipe_overlap(node, offsets)

    # Try signal pipes in order.
    # If connect fails try another.
    count = 0
    for i in range(0, len(offsets)):
        """
        The start location within the offset list
        depends on the technique no in the p2p_pipe
        so that a different start server can be used
        per method to skip failing on the same
        server every time. Adds more resilience.
        """
        offset = offsets[(i + (m - 1)) % len(offsets)]

        # Use existing sig pipe.
        if offset in node.signal_pipes:
            sig_pipe = node.signal_pipes[offset]

        # Or load new server offset.
        if offset not in node.signal_pipes:
            sig_pipe = await async_wrap_errors(
                load_signal_pipe(
                    node,
                    msg.routing.af,
                    offset,
                    MQTT_SERVERS
                )
            )

        # Failed.
        if sig_pipe is None:
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

async def sig_msg_queue_worker(node):
    print("in sig msg dispatcher")
    try:
        x = await node.sig_msg_queue.get()
        print("got sig msg q item", x)
        if x is None:
            return
        else:
            msg, vk, m = x
            if None in (msg, vk, m,):
                log(
                    "Invalid sig msg params = " + 
                    str(msg) + 
                    str(vk) + 
                    str(m)
                )
            print(msg, vk, m)
        
        await async_wrap_errors(
            send_sig_msg(
                node,
                msg,
                vk,
                m,
            )
        )

        node.sig_msg_queue_worker_task = create_task(
            node.sig_msg_queue_worker(node)
        )
    except RuntimeError:
        print("run time error in sig msg dispatcher")
        what_exception()
        log_exception()
        return
    
def start_sig_msg_queue_worker(node):
    # Route messages to destination.
    if node.sig_msg_queue_worker_task is None:
        node.sig_msg_queue_worker_task = create_task(
            node.sig_msg_queue_worker(node)
        )