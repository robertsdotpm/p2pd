from ...net.net import *

async def load_signal_pipe(node, af, offset, servers):
    # Lookup IP and port of MQTT server.
    server = servers[offset]
    dest_tup = (
        server[af],
        server["port"],
    )
    print(dest_tup)

    def sig_proto_closure():
        def closure(msg, signal_pipe):
            return signal_protocol(node, msg, signal_pipe)
    
        return closure

    """
    This function does a basic send/recv test with MQTT to help
    ensure the MQTT servers are valid.
    """
    print("load mqtt with self.node id:", node.node_id)
    client = await SignalMock(
        to_s(node.node_id),
        sig_proto_closure(),
        dest_tup
    ).start()

    if client is not None:
        node.signal_pipes[offset] = client

    print("mqtt client", client)

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
async def load_signal_pipes(self, node_id, servers=None, min_success=2, max_attempt_no=10):
    # Offsets for MQTT servers.
    servers = servers or MQTT_SERVERS
    offsets = [n for n in range(0, len(servers))]
    shuffled = []

    """
    The server offsets are put in a deterministic order
    based on the node_id. This is so restarting a server
    lands on the same signal servers and peers with the
    old address can still reach that node.
    """
    x = dhash(node_id)
    while len(offsets):
        pos = field_wrap(x, [0, len(offsets) - 1])
        index = offsets[pos]
        shuffled.append(index)
        offsets.remove(index)

    """
    Load the signal pipes based on the limit.
    """
    success_no = {IP4: 0, IP6: 0}
    supported_afs = self.supported()
    attempt_no = 0
    for index in shuffled:
        # Try current server offset against the clients supported AFs.
        # Skip if it doesn't support the AF.
        for af in supported_afs:
            # Update host IP if it's set.
            server = servers[index]
            if server["host"] is not None:
                try:
                    addr = await Address(server["host"], 123)
                    server[af] = addr.select_ip(af).ip
                except KeyError:
                    log_exception()

            # Skip unsupported servers.
            if server[af] is None:
                continue

            # Attempt to get a handle to the MQTT server.
            ret = await async_wrap_errors(
                self.load_signal_pipe(af, index, servers),
                timeout=2
            )

            # Valid signal pipe.
            if ret is not None:
                success_no[af] += 1

        # Find count of current successes.
        success_target = len(supported_afs) * min_success
        total_success = 0
        for af in supported_afs:
            total_success += success_no[af]

        # Exit if min loaded for supported AFs.
        if total_success >= success_target:
            break

        # There may be many MQTT -- don't try forever.
        # Safeguard to help prevent hangs.
        attempt_no += 1
        if attempt_no > max_attempt_no:
            break

def find_signal_pipe(self, addr):
    our_offsets = list(self.signal_pipes)
    for offset in addr["signal"]:
        if offset in our_offsets:
            return self.signal_pipes[offset]

    return None