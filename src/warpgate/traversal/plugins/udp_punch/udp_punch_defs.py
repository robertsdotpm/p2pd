"""Wire-format constants for the UDP punch CONFIRM probe.

The UDP punch engine fires datagrams at every predicted (peer_ext_ip,
peer_ext_port) tuple and listens on every locally-bound src_port for
inbound. To distinguish a real peer-from-NAT-mapping arrival from
random internet scanner traffic / NAT misroute, every probe carries a
fixed magic prefix + a session nonce both sides agreed on via the
PunchMsg exchange. CONFIRM is the second-leg ack: the receiver sees a
probe, fires CONFIRM back on the same 4-tuple, and the originator
locks the socket as the winner.

Frame layout (all big-endian):

    [0:4]   MAGIC = b"P2UP"
    [4]     KIND  -- 0x01 PROBE, 0x02 CONFIRM
    [5:21]  16-byte session nonce (must equal PunchMsg.nonce)

Total length: 21 bytes. The validator drops any datagram that doesn't
exactly match length + magic + matching nonce so application traffic
sharing the post-punch socket is not interfered with.
"""

UDP_PUNCH_MAGIC = b"P2UP"
UDP_PUNCH_KIND_PROBE = 0x01
UDP_PUNCH_KIND_CONFIRM = 0x02
UDP_PUNCH_NONCE_LEN = 16
UDP_PUNCH_FRAME_LEN = 4 + 1 + UDP_PUNCH_NONCE_LEN  # 21


def build_frame(kind, nonce):
    """Build a 21-byte UDP punch frame for the given kind + nonce."""
    if len(nonce) != UDP_PUNCH_NONCE_LEN:
        raise ValueError("nonce must be {0} bytes".format(UDP_PUNCH_NONCE_LEN))
    return UDP_PUNCH_MAGIC + bytes([kind]) + nonce


def parse_frame(buf):
    """Parse a UDP punch frame; returns (kind, nonce) or (None, None) on mismatch.

    Used by the engine to filter inbound datagrams: anything that
    doesn't match length+magic is application traffic that should
    pass through to the wrapping Pipe untouched.
    """
    if len(buf) != UDP_PUNCH_FRAME_LEN:
        return (None, None)
    if buf[:4] != UDP_PUNCH_MAGIC:
        return (None, None)
    return (buf[4], buf[5:5 + UDP_PUNCH_NONCE_LEN])
