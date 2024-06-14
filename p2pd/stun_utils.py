"""
support xor mapped addr
add the message integrity field


3489 -- needed for my nat test stuff
- not needed for my TCP code
i think that maybe the change requests and such have been remvoed based on recent rfcs

'RESPONSE-ADDRESS, CHANGED-ADDRESS, CHANGE-REQUEST, SOURCE-ADDRESS'

CHANGE-REQUEST attribute and on the address and port the
Binding Request was received on, and are summarized in Table 1.

TOdO: return bytearray().join([
create a pointer function for memory views.
?
"""

from struct import pack, unpack
import socket
from .utils import *
from .stun_defs import *
    
    
# Filter all other messages that don't match this.
def sub_stun_msg(tran_id, dest_tup):
    b_msg_p = re.escape(tran_id)
    b_addr_p = b"%s:%d" % (
        re.escape(
            to_b(dest_tup[0])
        ),
        dest_tup[1]
    )

    return [b_msg_p, b_addr_p]

# Extract either IPv4 or IPv6 addr from STUN attribute.
def extract_addr(buf, af=socket.AF_INET, base=20):
    # Config for ipv4 and ipv6.
    if af == socket.AF_INET:
        seg_no = 4
        seg_size = 1
        delim = "."
        form = lambda x: str(int(to_h(x), 16))
    else:
        seg_no = 8
        seg_size = 2
        delim = ":"
        form = lambda x: str(to_h(x))

    # Port part.
    p = 6
    port = int(to_h(buf[base + p:base + p + 2]), 16)
    p += 2

    # Binary encodes pieces of address.
    segments = []
    for i in range(0, seg_no):
        part = form(buf[base + p:base + p + seg_size])
        segments.append(part)
        p += seg_size

    # Return human readable version.
    ip = delim.join(segments)
    return [ip, port]

# Extract a tuple of a remote IP + port from a TURN attribute.
def turn_peer_attr_to_tup(peer_data, txid, af):
    if af == socket.AF_INET:
        # IPv4 and port.
        addr = TurnIPAddress(do_xor=True, xor_extra=txid).unpack(peer_data, family=b"\x00\x01")
    else:
        # IPv6 - needs extra XOR part.
        addr = TurnIPAddress(
            do_xor=True,
            xor_extra=txid
        ).unpack(peer_data, family=b"\x00\x02")

    return (addr.ip, int(addr.port))

def stun_proto(buf, af):
    # Initialize a list of dict keys with None.
    fields = ["resp", "rip", "rport", "sip", "sport", "cip", "cport"]
    ret = {} and [ret.setdefault(field, None) for field in fields]

    # Check buffer is min length to avoid overflows.
    if len(buf) < 20:
        log("Invalid buf len in main STUN res.")
        return

    # Only support certain message type.
    msgtype = buf[0:2]
    if msgtype != b"\1\1":
        log("> STUN unknown msg type %s" % (to_hs(msgtype)))
        return

    # Extract length of message attributes.
    len_message = int(to_h(buf[2:4]), 16)
    len_remain = len_message

    # Avoid overflowing buffer.
    if len(buf) - 20 < len_message:
        log("> Invalid message length recv for stun reply.")
        return

    # Start processing message attributes.
    log("> stun parsing bind = %d" % len_remain)
    base = 20
    ret['resp'] = True
    while len_remain > 0:
        # Avoid overflow for attribute parsing.
        if base + 4 >= len(buf):
            log("> new attr field overflow")
            break

        # Extract attributes from message buffer.
        attr_type = buf[base:(base + 2)]
        attr_len = int(to_h(buf[(base + 2):(base + 4)]), 16)

        # Avoid attribute overflows.
        if attr_len <= 0:
            log("> STUN attr len")
            break
        if attr_len + base + 4 > len(buf):
            log("> attr len overflow")
            break

        # Log attribute type.
        log("> STUN found attribute type = %s" % (to_hs(attr_type)))

        # Your remote IP and reply port. The important part.
        if attr_type == b'\0\1':
            ip, port = extract_addr(buf, af, base)
            ret['rip'] = ip
            ret['rport'] = port
            log(f"set mapped address {ip}:{port}")

        # Address that the STUN server would send change reqs from.
        if attr_type == b'\0\5':
            ip, port = extract_addr(buf, af, base)
            ret['cip'] = ip
            ret['cport'] = port
            log(f"set ChangedAddress {ip}:{port}")

        base = base + 4 + attr_len
        len_remain -= (4 + attr_len)

    return ret


def stun_proto2(buf, af):
    msg, buf = STUNMsg.unpack(buf)
    while not msg.eof():
        attr_code, _, attr_data = msg.read_attr()

        attr_name = buf_in_class(STUNAttrs, bytes(attr_code))
        print(attr_name)
        print(bytes(attr_code))
        print(bytes(attr_data))
        print()

        # Src port of UDP packet + external IP.
        # These details are XORed based on whether its IPv4 or IPv6.
        if attr_code == STUNAttrs.XorMappedAddress:
            if msg.mapped != []:
                continue

            msg.mapped = turn_peer_attr_to_tup(
                attr_data,
                msg.txn_id,
                self.turn_addr.af
            )
            log("> Turn setting mapped address = {}".format(self.mapped))
            self.client_tup_future.set_result(self.mapped)

    print(msg)

async def test_stun_utils():
    m = STUNMsg()
    buf = m.encode()

if __name__ == "__main__":
    async_test(test_stun_utils)