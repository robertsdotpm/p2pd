import asyncio
import re
from .ack_udp import *
from .net import *
from .ip_range import *

def tup_to_sub(dest_tup):
    dest_tup = client_tup_norm(dest_tup)
    return (
        b"", # Any message.
        dest_tup
    )

def norm_client_tup(client_tup):
    ip = ip_norm(client_tup[0])
    return (ip, client_tup[1])

"""
The code in this class supports a pull / fetch style use-case.
More suitable for some apps whereas the parent class allows
for handles to handle messages as they come in. The fetching
API needs for messages to be subscribed to beforehand.
"""
class PipeClient(ACKUDP):
    def __init__(self, pipe_events, loop=None, conf=NET_CONF):
        super().__init__()
        self.conf = conf
        self.dest = None
        self.dest_tup = None
        self.loop = loop or asyncio.get_event_loop()

        # [Bool(msg)] = Queue.
        # Lets convert this to [b"msg pattern", b"host pattern"] = [Queue]
        self.subs = {}

        # Instance of the base proto class.
        self.pipe_events = pipe_events
        self.route = self.pipe_events.route

        # Used for doing send calls.
        self.handle = {}

    """
    (1) UDP is multiplexed and doesn't need a destination bound.
    (2) TCP cons have a dest set.
    (3) TCP and UDP servers won't have a dest.
    """
    def set_dest_tup(self, dest_tup):
        dest_tup = client_tup_norm(dest_tup)
        self.dest_tup = dest_tup

    """
    Set internal handle used for doing sends.
    For UDP this is a asyncio.DatagramTransport.
    For TCP it's a asyncio.StreamWriter.
    """
    def set_handle(self, handle, client_tup=None):
        if client_tup is not None:
            client_tup = client_tup_norm(client_tup)
            self.handle[client_tup] = handle
        else:
            self.handle = handle

    def hash_sub(self, sub):
        h = hash(sub[0])
        if sub[1] is not None:
            client_tup_str = f"{sub[1][0]}:{sub[1][1]}"
            h += hash(client_tup_str)

        return h

    # Subscribe to a certain message and host type.
    # sub = [b_msg_pattern, b_addr_pattern]
    # optional: 3rd field in sub = example match
    def subscribe(self, sub, handler=None):
        b_msg_p, client_tup = sub
        if client_tup is not None:
            assert(isinstance(client_tup[1], int))
            client_tup = norm_client_tup(client_tup)
            sub = (b_msg_p, client_tup)

        offset = self.hash_sub(sub)
        if offset not in self.subs:
            self.subs[offset] = [
                sub,
                asyncio.Queue(self.conf["max_qsize"]),
                handler
            ]

        return offset

    # Remove a subscription.
    def unsubscribe(self, sub):
        offset = self.hash_sub(sub)
        if offset in self.subs:
            del self.subs[offset]

        return self

    # Adds a message to the first valid bucket.
    """
    TODO: If the queue is full what should the default
    actions be? Should the program await the queue
    being empty? Should it discard data? Maybe on limit - 1
    call https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.loop.remove_reader and on queue empty add it back.
    """
    def add_msg(self, data, client_tup):
        # No subscriptions.
        if not len(self.subs):
            return
        
        # Norm compressed IPv6 addresses.
        client_tup = client_tup_norm(client_tup)

        # Add message to queue and raise an event.
        def do_add(q):
            # Check queue isn't full.
            if q.full():
                # TODO: Remove sock from event select.
                # To give time for queue to be processed.
                q.get_nowait()

            # Put an item on the queue.
            assert(isinstance(client_tup, tuple))
            q.put_nowait([client_tup, data])

        # Apply bool filters to message.
        msg_added = False
        for sub, q, handler in self.subs.values():
            # Msg pattern, address pattern.
            b_msg_p, m_client_tup = sub[:2]

            # Check client_addr matches their host pattern.
            if m_client_tup is not None:
                # Also check the source port.
                assert(isinstance(m_client_tup[1], int))
                if m_client_tup[1]:
                    if m_client_tup != client_tup:
                        continue

                # Ignore source port but check IPs.
                if not m_client_tup[1]:
                    if m_client_tup[0] != client_tup[0]:
                        continue

            # Check data matches their message pattern.
            if b_msg_p:
                msg_matches = re.findall(b_msg_p, data)
                if msg_matches == []:
                    continue

            # Execute message using handle instead of adding to queue.
            if handler is not None:
                run_handler(
                    self.pipe_events,
                    handler,
                    client_tup,
                    data
                )

                continue

            # Add message to queue.
            msg_added = True
            do_add(q)

        if not msg_added:
            log(f"Discarded {client_tup} = {data}")

    # Async wait for a message that matches a pattern in a queue.
    async def recv(self, sub=SUB_ALL, timeout=2, full=False):
        recv_timeout = timeout or self.conf["recv_timeout"]
        msg_p, addr_p = sub
        if addr_p is not None:
            assert(isinstance(addr_p[1], int))
            addr_p = client_tup_norm(addr_p)
            sub = (msg_p, addr_p)

        offset = self.hash_sub(sub)
        try:
            # Sanity checking.
            if offset not in self.subs:
                raise Exception("Sub not found. Forgot to subscribe.")

            # Get message from queue with timeout.
            _, q, handler = self.subs[offset]
            ret = await asyncio.wait_for(
                q.get(),
                recv_timeout
            )

            # Run handler if one is set.
            if handler is not None:
                run_handler(
                    self.pipe_events,
                    handler,
                    ret[0],
                    ret[1]
                )

            # Return data, sender_tup.
            if full:
                return ret
            else:
                # Return only the data portion.
                return ret[1]
        except Exception as e:
            return None

    # Async send for TCP and UDP cons.
    # Listen servers also supported.
    async def send(self, data, dest_tup):
        dest_tup = client_tup_norm(dest_tup)
        try:
            # Get handle reference.
            if isinstance(self.handle, dict):
                handle = self.handle[dest_tup]
            else:
                handle = self.handle

            # TCP send -- already bound to a target.
            # Indexed by writer streams per con.
            if isinstance(handle, asyncio.streams.StreamWriter):
                handle.write(data)
                await handle.drain()
                return 1

            # UDP send -- not connected - can be sent to anyone.
            # Single handle for multiplexing.
            if isinstance(handle, DATAGRAM_TYPES):
                handle.sendto(
                    data,
                    dest_tup
                )
                return 1

            # TCP send -- already bound to transport con.
            # TCP Transport instance.
            if isinstance(handle, STREAM_TYPES):
                # This also works for SSL wrapped sockets.
                handle.write(data)
                """
                await self.loop.sock_sendall(
                    self.pipe_events.sock,
                    data
                )
                """
                

                return 1

            return 0
        except Exception as e:
            log(f" send error {self.handle}")
            log_exception()
            return 0
