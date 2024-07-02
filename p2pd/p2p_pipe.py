import asyncio
import copy
from .p2p_addr import *
from .tcp_punch import *
from .turn_client import *
from .signaling import *
from .p2p_utils import *
from .p2p_protocol import *

"""
TCP 
nc -4 -l 127.0.0.1 10001 -k
nc -6 -l ::1 10001 -k
"""

P2P_DIRECT = 1
P2P_REVERSE = 2
P2P_PUNCH = 3
P2P_RELAY = 4

# TURN is not included as a default strategy because it uses UDP.
# It will need a special explanation for the developer.
# SOCKS might be a better protocol for relaying in the future.
P2P_STRATEGIES = [P2P_DIRECT, P2P_REVERSE, P2P_PUNCH]

def build_reverse_msg(pipe_id, addr_bytes, b_proto=b"TCP"):
    out = b"P2P_DIRECT %s %s %s" % (pipe_id, b_proto, addr_bytes) 
    return out

def build_punch_response(cmd, pipe_id, punch_ret, src_addr_bytes, af, our_if_index, their_if_index):
    def mappings_to_bytes(mappings):
        pairs = []
        for pair in mappings:
            # remote, reply, local.
            pairs.append( b"%d,%d,%d" % (pair[0], pair[1], pair[2]) )

        return b"|".join(pairs)

    #      cm pip se nt pr ad af (if indexs)
    out = b"%s %s %d %s %s %s %d %d %d" % (
        cmd,
        pipe_id,
        0, # session id.
        to_b(str(punch_ret[1])), # ntp
        mappings_to_bytes(punch_ret[0]), # predictions
        src_addr_bytes,
        af,
        our_if_index,
        their_if_index
    )

    return out

def parse_prediction_str(s_predictions):
    predictions = []
    prediction_strs = s_predictions.split("|")
    for prediction_str in prediction_strs:
        remote_s, reply_s, local_s = prediction_str.split(",")
        prediction = [to_n(remote_s), to_n(reply_s), to_n(local_s)]
        if not in_range(prediction[0], [1, MAX_PORT]):
            raise Exception(f"Invalid remote port {prediction[0]}")

        if not in_range(prediction[-1], [1, MAX_PORT]):
            raise Exception(f"Invalid remote port {prediction[-1]}")

        predictions.append(prediction)

    if not len(predictions):
        raise Exception("No predictions received.")

    return predictions

def parse_punch_response(parts):
    return {
        "cmd": parts[0],
        "pipe_id": to_b(parts[1]),
        "session_id": to_n(parts[2]),
        "ntp_time": Dec(parts[3]),
        "predictions": parse_prediction_str(parts[4]),
        "src_addr": parse_peer_addr(to_b(parts[5])),
        "src_addr_bytes": to_b(parts[5]),
        "af": to_n(parts[6]),
        "if": {
            "them": to_n(parts[7]),
            "us": to_n(parts[8])
        }
    }

f_punch_index = lambda ses, addr, pipe: b"%d %b %b" % (ses, addr, pipe)
class P2PPipe():
    def __init__(self, node):
        self.node = node
        self.tasks = []

    # Minor data structure cleanup.
    def cleanup_pipe(self, pipe_id):
        def closure():
            if pipe_id in self.node.pipes:
                del self.node.pipes[pipe_id]

        return closure

    # Waits for a pipe event to fire.
    # Returns the corrosponding pipe.
    async def pipe_waiter(self, pipe_id, timeout=0):
        try:
            pipe_event = self.node.pipe_events[pipe_id]
            if timeout:
                await asyncio.wait_for(
                    pipe_event.wait(),
                    timeout
                )
            else:
                await pipe_event.wait()
            pipe = self.node.pipes[pipe_id]
            return pipe
        except asyncio.TimeoutError:
            log(f"> Pipe waiter timeout {pipe_id} {timeout}")
            return None
        
    # Implements the p2p connection techniques.
    async def open_pipe(self, pipe_id, dest_bytes, strategies=P2P_STRATEGIES):
        print(f"> Pipe open = {pipe_id}; {dest_bytes}; {strategies}")


        # Setup events for waiting on the pipe.
        pipe = None
        p2p_dest = parse_peer_addr(dest_bytes)
        self.node.pipe_events[pipe_id] = asyncio.Event()

        # See if a matching signal pipe exists.
        signal_pipe = self.node.find_signal_pipe(p2p_dest)
        if signal_pipe is None:
            log("Signal pipe is none")
            for offset in p2p_dest["signal"]:
                # Build a channel used to relay signal messages to peer.
                mqtt_server = MQTT_SERVERS[offset]
                signal_pipe = SignalMock(
                    peer_id=to_s(self.node.node_id),
                    f_proto=self.node.signal_protocol,
                    mqtt_server=mqtt_server
                )

                # If it fails unset the client.
                try:
                    # If it's successful exit server offset attempts.
                    await signal_pipe.start()
                    self.node.signal_pipes[offset] = signal_pipe
                    break
                except asyncio.TimeoutError:
                    # Cleanup and make sure it's unset.
                    await signal_pipe.close()
                    signal_pipe = None

        # Check if a signal pipe was found.
        if signal_pipe is None:
            raise Exception("Unable to open same signal pipe as peer.")

        # Patch dest address if it's behind same router.
        dest_patch = work_behind_same_router(self.node.p2p_addr, p2p_dest)
        print(f"{dest_patch} dest_patch")
        timeout = 0
        for strategy in strategies:
            # Try connect directly to peer.
            if strategy == P2P_DIRECT:
                timeout = 4
                print("try p2p direct")
                open_task = self.direct_connect(dest_patch, pipe_id)

            # Tell the peer to try connect to us.
            if strategy == P2P_REVERSE:
                # Associate the pending pipe with external IP(s).
                exts = peer_addr_extract_exts(p2p_dest)
                self.node.expected_addrs[pipe_id] = exts

                # Instruct the peer to do the reverse connect.
                out = build_reverse_msg(pipe_id, self.node.addr_bytes)
                await signal_pipe.send_msg(
                    out,
                    to_s(p2p_dest["node_id"])
                )

                # Wait for the new pipe to appear.
                timeout = 10
                open_task = self.pipe_waiter(pipe_id)

            # Do TCP hole punching to try connect.
            if strategy == P2P_PUNCH:
                # Start TCP hole punching.
                self.tasks.append(
                    asyncio.create_task(
                        async_wrap_errors(
                            self.tcp_hole_punch(dest_patch, pipe_id, signal_pipe)
                        )
                    )
                )

                # Wait for the hole to appear.
                """
                Meet delay = 3
                Punch duration = 3
                Update wait = 4
                Init wait = 4
                Padding = 6
                """
                timeout = 30
                open_task = self.pipe_waiter(pipe_id)

            # Use a TURN server to connect to a peer.
            if strategy == P2P_RELAY:
                # 3 retries, up to 10 secs for each attempt.
                timeout = 45
                open_task = self.udp_relay(p2p_dest, pipe_id, signal_pipe)

            # Got valid pipe so return it.
            pipe = await async_wrap_errors(open_task, timeout)
            print("output from open task = ")
            print(pipe)
            if pipe is not None:
                print(f"> Got pipe = {pipe.sock} from {pipe.route} using {strategy}.")
                return [pipe, strategy]


        print("Got pipe = ")
        print(pipe)
        log(f"> Uh oh, pipe was None.")
        return [pipe, None]

    # Main function for scheduling p2p connections.
    async def pipe(self, dest_bytes, timeout=60, strategies=P2P_STRATEGIES):
        # Identify a pipe.
        strategy = p2p_pipe = None
        pipe_id = rand_plain(15)
        assert(isinstance(pipe_id, bytes))

        # Wrap open pipe in a task so it can be cancelled.
        task = asyncio.create_task(
            async_wrap_errors(
                self.open_pipe(pipe_id, dest_bytes, strategies)

            )
        )

        # Record the task in a pending state.
        self.node.pending_pipes[pipe_id] = task
        try:
            await asyncio.wait_for(
                task,
                timeout
            )
            p2p_pipe, strategy = task.result()
        except Exception:
            log_exception()

        print("in pipe")
        print(p2p_pipe)
        print(strategy)

        # When it's done delete the pending reference.
        if pipe_id in self.node.pending_pipes:
            del self.node.pending_pipes[pipe_id]
            
        return [p2p_pipe, strategy]

    """
    Peer A and peer B both have a list of interface info
    for each address family. Each interface connected to
    a unique gateway will have its own NAT characteristics.
    The challenge is to prioritize which combination of
    peer interfaces is most favorable given the interplay
    between their corresponding NAT qualities.

    The least restrictive NATs are assigned a lower
    value. So the start of the algorithm just groups together
    the lowest value pairs and runs through them until one
    succeeds.
    """
    async def tcp_hole_punch(self, af, pipe_id, node_id, src_info, dest_info, dest_bytes):
        # Punch clients indexed by interface offset.
        if_index = src_info["if_index"]
        interface = self.node.ifs[if_index]
        initiator = self.node.tcp_punch_clients[if_index]

        # Select [ext or nat] dest and punch mode
        # (either local, self, remote)
        punch_mode, use_addr = await get_punch_mode(
            af,
            dest_info,
            interface,
            initiator,
        )

        print("alice punch mode")
        print(punch_mode)
        print(use_addr)

        # Get initial NAT predictions using STUN.
        stun_client = self.node.stun_clients[af][if_index]
        punch_ret = await initiator.proto_send_initial_mappings(
            use_addr,
            dest_info["nat"],
            node_id,
            pipe_id,
            stun_client,
            mode=punch_mode
        )

        """
        Punching is delayed for a few seconds to
        ensure there's enough time to receive any
        updated mappings for the dest peer (if any.)
        """
        asyncio.ensure_future(
            self.node.schedule_punching_with_delay(
                if_index,
                pipe_id,
                node_id,
            )
        )

        # Initial step 1 punch message.
        msg = TCPPunchMsg({
            "meta": {
                "pipe_id": pipe_id,
                "af": af,
                "src_buf": self.node.addr_bytes,
                "src_index": 0,
            },
            "routing": {
                "af": af,
                "dest_buf": dest_bytes,
                "dest_index": 0,
            },
            "payload": {
                "punch_mode": punch_mode,
                "ntp": punch_ret[1],
                "mappings": punch_ret[0],
            },
        })

        # Basic dest addr validation.
        msg.set_cur_addr(self.node.addr_bytes)
        msg.routing.load_if_extra(self.node)
        msg.validate_dest(af, punch_mode, use_addr)
        return msg

    async def udp_relay(self, af, pipe_id, node_id, src_info, dest_info, dest_bytes):
        # Try TURN servers in random order.
        offsets = list(range(0, len(TURN_SERVERS)))
        random.shuffle(offsets)

        # Attempt to connect to TURN server.
        peer_tup = relay_tup = turn_client = None
        for offset in offsets:
            try:
                peer_tup, relay_tup, turn_client = await get_turn_client(
                    af,
                    offset,
                    self.node.ifs[src_info["if_index"]]
                )
            except:
                log_exception()
                continue

            if turn_client is not None:
                self.node.pipe_future(pipe_id)
                self.node.turn_clients[pipe_id] = turn_client
                return TURNMsg({
                    "meta": {
                        "pipe_id": pipe_id,
                        "af": af,
                        "src_buf": self.node.addr_bytes,
                        "src_index": src_info["if_index"],
                    },
                    "routing": {
                        "af": af,
                        "dest_buf": dest_bytes,
                        "dest_index": dest_info["if_index"],
                    },
                    "payload": {
                        "peer_tup": peer_tup,
                        "relay_tup": relay_tup,
                        "serv_id": offset,
                    },
                })

if __name__ == "__main__": # pragma: no cover
    async def test_p2p_con():
        p2p_dest = None
        if1 = await Interface("enp3s0").start()
        if_list = [if1]
        pipe_id = rand_plain(10)
        p2p_pipe = P2PPipe(if_list, 0)
        await p2p_pipe.direct_connect(p2p_dest, pipe_id, proto=TCP)


        while 1:
            await asyncio.sleep(1)

    async_test(test_p2p_con)