from aionetiface import *
from .signal_client import SignalMock

def find_signal_pipe(node, addr):
    our_offsets = list(node.signal_pipes)
    for offset in addr["signal"]:
        if offset in our_offsets:
            return node.signal_pipes[offset]

    return None

# Make already loaded sig pipes first to try.
def prioritize_sig_pipe_overlap(node, offsets):
    overlap = []
    non_overlap = []
    for offset in offsets:
        if offset in node.signal_pipes:
            overlap.append(offset)
        else:
            non_overlap.append(offset)

    return overlap + non_overlap

async def load_signal_pipe(node_id, af, offset, servers, msg_cb=None):
    # Lookup IP and port of MQTT server.
    server = servers[offset]
    dest_tup = (server[af], server["port"],)
    """
    This function does a basic send/recv test with MQTT to help
    ensure the MQTT servers are valid.
    """
    msg_cb = msg_cb or (lambda x, y, z: None)
    client = await SignalMock(
        to_s(node_id),
        msg_cb,
        dest_tup
    ).start()

    return client


"""
There's a massive problem with the MQTT client
library. Starting it must use threading or do
something funky with the event loop.
It seems that starting the MQTT clients
sequentially prevents errors with queues being
bound to the wrong event loop.

TODO: investigate this.
TODO: maybe load MQTT servers concurrently.
"""
async def load_signal_pipes(node, node_id, servers=None, min_success=2, max_attempt_no=3):
    servers = servers or MQTT_SERVERS
    offsets = [n for n in range(0, len(servers))]
    shuffled = []

    # Deterministic shuffle
    x = dhash(node_id)
    while offsets:
        pos = field_wrap(x, [0, len(offsets) - 1])
        index = offsets[pos]
        shuffled.append(index)
        offsets.remove(index)

    supported_afs = node.supported()
    success_no = {af: 0 for af in supported_afs}

    batch_size = min_success + 2
    attempt_no = 0
    cursor = 0

    async def try_one(af, index):
        server = servers[index]
        if server[af] is None:
            return None, af
        
        ret = await async_wrap_errors(
            load_signal_pipe(
                node_id, 
                af, 
                index, 
                servers
            ),
            timeout=2
        )

        if ret is not None:
            node.signal_pipes[index] = ret

        return ret, af

    def met_requirements():
        for af in supported_afs:
            if success_no[af] < min_success:
                return False
        return True

    while cursor < len(shuffled):
        if attempt_no > max_attempt_no:
            break

        batch = shuffled[cursor:cursor + batch_size]
        cursor += batch_size
        attempt_no += 1

        tasks = []
        for index in batch:
            for af in supported_afs:
                if servers[index][af] is None:
                    continue
                tasks.append(try_one(af, index))

        if not tasks:
            continue

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                continue
            ret, af = r
            if ret is not None:
                success_no[af] += 1

        if met_requirements():
            break

def try_unpack_msg(buf, sk, sig_proto_map):
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
    msg_info = sig_proto_map[buf[0]]
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

def sig_msg_to_buf(msg):
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
    return buf

