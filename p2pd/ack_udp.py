import asyncio
import struct
import random
from struct import pack
from .utils import *

UDP_MAX_DICT_LEN = 1000

"""
Extended functionality to allow the UDP stream class
to provide 'reliable' packet delivery. It uses message
IDs for each message and acknowledgements. It doesn't
guarantee ordered delivery. Inherited by udp_stream.
"""

class ACKUDP():
    def __init__(self):
        self.seq = {} # Waiting for acks.
        self.ack_send_tasks = []

    # Returns a sequence number if a message is an ack.
    def is_ack(self, data, stream):
        if len(data) >= 9:
            seq, = struct.unpack("!Q", data[0:8])
            is_ack = data[8]
            if is_ack == 1:
                return seq

        return None

    # Received message that needs to be acked.
    # Return its sequence number and valid ack response.
    def is_ackable(self, data, stream):
        payload = ack = is_ack = seq = None
        if len(data) >= 9:
            seq, = struct.unpack("!Q", data[0:8])
            is_ack = data[8]
        else:
            return [None, None, None]

        if is_ack == 0:
            # Build ack message to send in response.
            ack = struct.pack("!Q", seq) + struct.pack("!B", 1)

        return [seq, ack, data[9:]]

    """
    Clients that receive a message that can be 'acked' now
    send back the ack every time they receive a message even
    if they have already acked. This makes more sense as we
    don't know if the receiver has actually gotten the ack
    yet. Keep code to skip acking if a peer sent a message.
    This prevents getting into loops for the sender.
    """
    def handle_ack(self, data, f_is_ack, f_is_ackable, f_send):
        self.ack_send_tasks = rm_done_tasks(self.ack_send_tasks)
        data = data
        payload = recv_seq = ack_seq = ack = None
        self.timestamp = timestamp()

        # If this message is an ack then record its seq no.
        if f_is_ack is not None:
            ack_seq = f_is_ack(data, self)
            if ack_seq is not None:
                if ack_seq in self.seq:
                    self.seq[ack_seq].set()

                return 0, payload

        # If it's a regular message check if it needs
        # to be acknowledged and record the seq no.
        if f_is_ackable is not None:
            recv_seq, ack, payload = f_is_ackable(data, self)
            if payload is None:
                return 0, None

            if ack is not None:
                # Seq is set when sending.
                # If they give us back our seq take it as an ACK
                # even if they didn't set the ACK flag.
                if recv_seq in self.seq:
                    # Pretend we received an ACK for our message.
                    self.seq[recv_seq].set()

                    # Don't broadcast an ACK for this.
                    ack = None

        # Keep dicts from taking up too much memory.
        if len(self.seq) > UDP_MAX_DICT_LEN:
            self.seq = {}

        """
        The TURN client implements a custom is_ackable that wraps an ACK
        in a channel message which allows the server to deliver the message.
        """
        if ack is not None:
            task = asyncio.create_task(
                async_wrap_errors(
                    f_send(ack)
                )
            )

            self.ack_send_tasks.append(task)
            return 2, payload

        return 1, payload

    """
    A function that retransmits a UDP packet up to 'tries' time or
    'sock_timeout' duration. If a special acknowledgement is received
    before an error condition - the function returns successfully with
    a value of 0 (no errors.) The code uses events to wait on ACKs
    so there are no inefficient busy-loop checks.
    """
    async def ack_send(self, data, dest_tup, seq=None, sock_timeout=0, tries=3):
        # Keep sending until max sends reached.
        # For acks we send max transmits as they're small messages.
        if seq is None:
            seq = random.randrange(1, (2 ** (8 * 8)))

        """
        Mark all messages we send in the same data structure clients
        use to indicate whether they have acknowledged a message.
        This prevents the sender from getting into loops.
        """
        event = asyncio.Event()
        self.seq[seq] = event

        # Do the sending concurrently so event can be returned.
        async def worker():
            # Record when the process started.
            start = 0
            if sock_timeout:
                start = timestamp()

            # Build data to send.
            buf = bytearray().join([
                pack("!Q", seq),
                pack("!B", 0),
                memoryview(data)
            ])

            # Await on ACK events.
            # Break on transmits >= tries, timeout, or success.
            send_transmits = 0
            while True:
                # Initial send.
                await self.send(buf, dest_tup)
                send_transmits += 1

                # Finish trying to send.
                # First failure mode reached.
                if send_transmits >= tries:
                    break

                # Recheck for ack every second.
                try:
                    # Will return instantly on receiving a related ACK.
                    # Otherwise it suspends for other code to execute.
                    await asyncio.wait_for(
                        self.seq[seq].wait(),
                        3
                    )

                    # No timeout error = success.
                    break
                except asyncio.TimeoutError:
                    pass

                # Too much time passed.
                # Second failure mode reached.
                if sock_timeout:
                    elapsed = timestamp() - start
                    if elapsed >= sock_timeout:
                        break

            # Do cleanup.
            if seq in self.seq:
                del self.seq[seq]

        # Schedule sending task.
        task = asyncio.create_task(worker())
        self.ack_send_tasks.append(task)

        # Wait for ACK.
        return task, event

class BaseACKProto(asyncio.Protocol):
    def __init__(self, conf):
        self.conf = conf

    # Supports dropping duplicate messages.
    def is_unique_msg(self, pipe, data, client_tup):
        # Reset seen msgs after dict fills.
        if len(self.msg_ids) > self.conf["max_msg_ids"]:
            self.msg_ids = {}

        # Record msg -- drop if already seen.
        # Route by client endpoint.
        # Seen messages are per client IP.
        buf = to_b(client_tup[0]) + data

        """
        I use Pythons insecure hash function.
        A cryptographically secure hash func
        would absolutely destroy the event
        loops performance! E.g. 100 ms+ per hash,
        per message received = yikes.
        """
        msg_id = hash(buf)
        if msg_id in self.msg_ids:
            return 0
        else:
            self.msg_ids[msg_id] = 1
            return 1