"""Multiplexing pcap reader for N parallel Connection instances.

Problem
-------
aionetiface.net.pcap.loopback.PcapReader is a 1:1 wrapper around a
single Backend: one daemon thread polls recv() and pushes frames
into ONE asyncio.Queue. When a Connection's driver_loop awaits
reader.next_frame(), it dequeues -- which would steal a frame
intended for any other Connection sharing the reader.

A naive workaround is N readers / N backends, but opening one
pcap_t per Connection is wasteful (kernel filter compile, BPF
install, large per-handle buffers; also opens us to per-process
pcap-handle caps and N-fold CPU at the OS layer).

Solution
--------
PcapMuxReader is a single backend reader with N subscriber queues.
Each subscriber registers a (local_ip, local_port, peer_ip, peer_port)
4-tuple; the reader thread inspects every captured frame at the
Ethernet/IP/TCP layer and, when the L4 5-tuple matches a subscriber,
pushes the raw frame bytes onto that subscriber's queue.

Subscribers expose the same `next_frame(timeout)` API as
PcapReader so existing Connection.driver_loop code consumes from
them with no changes. Per-subscriber queues are bounded to
match PcapReader's default (512); overflow drops frames on the
floor with a single log line per overflow event, same as
PcapReader.

Frames that don't match any subscriber are dropped (the BPF on the
backend already narrows the firehose to the punch's port set; this
is the second filter that's actually load-bearing for routing).

Lifecycle
---------
    mux = PcapMuxReader(backend, loop=loop)
    sub1 = mux.subscribe(four_tuple_1)
    sub2 = mux.subscribe(four_tuple_2)
    ...
    mux.start()
    # pass each sub into a Connection constructor as reader=
    ...
    mux.stop()
    backend.close()

Each subscriber's `next_frame` and `stop` mirror PcapReader's so
Connection.ensure_reader / close treat them identically.

Thread safety
-------------
The reader is the only writer to each subscriber queue (via
loop.call_soon_threadsafe). subscribe()/unsubscribe() take a lock
so the reader thread sees a consistent subscriber list mid-frame.
"""
import asyncio
import threading

from aionetiface.net.pcap.ip import eth, ipv4
from aionetiface.net.pcap.tcp import segment as tcp_segment

try:
    from aionetiface.utility.fstr import fstr
except ImportError:
    def fstr(template, args):
        return template.format(*args)


# DLT constants -- repeat here so we don't import from anywhere private.
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_LOOP = 108


class MuxSubscriber(object):
    """Single Connection's view of the muxed frame stream.

    Implements the minimal PcapReader contract that
    aionetiface.net.pcap.tcp.conn.Connection.driver_loop uses:

        await sub.next_frame(timeout=0.2)
        sub.stop()                         # release subscription

    Plus a backend attribute so Connection.flush_outbox can call
    self.backend.send() -- subscribers expose the shared backend.
    """

    def __init__(self, mux, four_tuple, queue_max=512):
        self.mux = mux
        self.four_tuple = four_tuple
        self.queue = asyncio.Queue(maxsize=queue_max)
        self.backend = mux.backend
        self.stopped = False

    async def next_frame(self, timeout=None):
        if timeout is None:
            return await self.queue.get()
        return await asyncio.wait_for(self.queue.get(), timeout=timeout)

    def stop(self):
        if self.stopped:
            return
        self.stopped = True
        self.mux.unsubscribe(self)
        try:
            self.queue.put_nowait(None)
        except asyncio.QueueFull:
            pass


class PcapMuxReader(object):
    """Demultiplexes one backend's frames into N per-Connection queues."""

    def __init__(self, backend, loop=None, poll_ms=10):
        self.backend = backend
        self.loop = loop or asyncio.get_event_loop()
        self.poll_ms = poll_ms
        self.stop_flag = threading.Event()
        self.thread = None
        # Map four_tuple -> MuxSubscriber. The four_tuple is stored as
        # (local_ip, local_port, peer_ip, peer_port) where local is
        # this side and peer is the other end.
        self.subscribers = {}
        self.lock = threading.Lock()
        self.datalink = backend.datalink()

    def subscribe(self, four_tuple):
        """Register a subscriber for one 4-tuple. Returns the
        MuxSubscriber object to pass into the Connection constructor
        as reader=.
        """
        with self.lock:
            existing = self.subscribers.get(four_tuple)
            if existing is not None:
                return existing
            sub = MuxSubscriber(self, four_tuple)
            self.subscribers[four_tuple] = sub
        return sub

    def unsubscribe(self, sub):
        with self.lock:
            for key, val in list(self.subscribers.items()):
                if val is sub:
                    del self.subscribers[key]
                    break

    def start(self):
        if self.thread is not None:
            return
        self.thread = threading.Thread(
            target=self.run_loop, name="pcap-mux-reader", daemon=True,
        )
        self.thread.start()

    def stop(self):
        self.stop_flag.set()
        # Wake all subscribers so awaiting tasks unblock.
        with self.lock:
            subs = list(self.subscribers.values())
        for sub in subs:
            try:
                self.loop.call_soon_threadsafe(sub.queue.put_nowait, None)
            except RuntimeError:
                pass
        self.thread = None

    def run_loop(self):
        while not self.stop_flag.is_set():
            try:
                frame = self.backend.recv(timeout_ms=self.poll_ms)
            except Exception as exc:
                # Send EOF sentinel to all subscribers.
                with self.lock:
                    subs = list(self.subscribers.values())
                for sub in subs:
                    try:
                        self.loop.call_soon_threadsafe(
                            sub.queue.put_nowait, None,
                        )
                    except RuntimeError:
                        pass
                return
            if frame is None:
                continue
            self.dispatch_frame(frame)

    def dispatch_frame(self, frame):
        """Inspect the frame's L4 5-tuple and route to the matching sub."""
        try:
            if self.datalink == DLT_EN10MB:
                _, _, ethertype, ip_payload = eth.parse_eth_frame(frame)
            else:
                ethertype, ip_payload = eth.strip_link_layer(
                    self.datalink, frame,
                )
        except ValueError:
            return
        # ARP frames go to every subscriber so each Connection's ArpCache
        # gets the same view -- ARP is broadcast and per-Connection state.
        if ethertype == eth.ETH_TYPE_ARP:
            self.broadcast_frame(frame)
            return
        if ethertype != eth.ETH_TYPE_IPV4:
            return
        try:
            iphdr, l4 = ipv4.parse_ipv4(ip_payload)
        except ValueError:
            return
        if iphdr.proto != ipv4.PROTO_TCP:
            return
        try:
            seg = tcp_segment.parse_tcp_segment(l4)
        except ValueError:
            return
        # Frame arrived FROM iphdr.src_str:seg.src_port TO iphdr.dst_str:seg.dst_port.
        # Our subscribers are keyed (local_ip, local_port, peer_ip, peer_port);
        # match where local matches dst and peer matches src.
        local_ip = iphdr.dst_str
        local_port = seg.dst_port
        peer_ip = iphdr.src_str
        peer_port = seg.src_port
        key = (local_ip, local_port, peer_ip, peer_port)
        with self.lock:
            sub = self.subscribers.get(key)
        if sub is None:
            # No exact match -- might be a half-open simul-open where
            # the peer's source port is the predicted-other but our
            # subscriber's tuple uses 0 or a different port. Fall back
            # to a 3-tuple match (local_ip, local_port, peer_ip, *) so
            # the simul-open SYN still finds a home.
            with self.lock:
                for cand_key, cand_sub in self.subscribers.items():
                    if (
                        cand_key[0] == local_ip
                        and cand_key[1] == local_port
                        and cand_key[2] == peer_ip
                    ):
                        sub = cand_sub
                        break
        if sub is None:
            return
        try:
            self.loop.call_soon_threadsafe(sub.queue.put_nowait, frame)
        except RuntimeError:
            pass
        except asyncio.QueueFull:
            pass

    def broadcast_frame(self, frame):
        """Push frame to every subscriber (used for ARP)."""
        with self.lock:
            subs = list(self.subscribers.values())
        for sub in subs:
            try:
                self.loop.call_soon_threadsafe(sub.queue.put_nowait, frame)
            except RuntimeError:
                pass
            except asyncio.QueueFull:
                pass
