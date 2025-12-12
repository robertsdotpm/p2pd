from ...settings import *
from ...net.net_utils import *
from ...net.address import Address
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

async def load_signal_pipe(node, af, offset, servers):
    # Lookup IP and port of MQTT server.
    server = servers[offset]
    dest_tup = (
        server[af],
        server["port"],
    )
    #print(dest_tup)

    """
    This function does a basic send/recv test with MQTT to help
    ensure the MQTT servers are valid.
    """
    #print("load mqtt with self.node id:", node.node_id)

    client = await SignalMock(
        to_s(node.node_id),
        lambda x, y, z: None,
        dest_tup
    ).start()

    if client is not None:
        node.signal_pipes[offset] = client

    #print("mqtt client", client)

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
            load_signal_pipe(node, af, index, servers),
            timeout=2
        )
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
