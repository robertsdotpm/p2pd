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
def sub_to_stun_reply(tran_id, dest_tup):
    b_msg_p = re.escape(tran_id)
    b_addr_p = b"%s:%d" % (
        re.escape(
            to_b(dest_tup[0])
        ),
        dest_tup[1]
    )

    return [b_msg_p, b_addr_p]

def stun_proto(buf, af):
    msg, buf = STUNMsg.unpack(buf)
    while not msg.eof():
        attr_code, _, attr_data = msg.read_attr()
        attr_name = buf_in_class(STUNAttrs, bytes(attr_code))
        """
        print(attr_name)
        print(bytes(attr_code))
        print(bytes(attr_data))
        print()
        """
        
        # Set our remote IP and port.
        if not hasattr(msg, "rtup"):
            xor_addr_attrs = [STUNAttrs.XorMappedAddressX, STUNAttrs.XorMappedAddress]
            if attr_code in xor_addr_attrs:
                stun_addr_field = STUNAddrTup(
                    af=af,
                    txid=msg.txn_id,
                    magic_cookie=msg.magic_cookie,
                ).unpack(attr_code, stun_addr_field.tup)
                msg.rtup = stun_addr_field.tup

            if attr_code == STUNAttrs.MappedAddress:
                stun_addr_field = STUNAddrTup(
                    af=af
                ).unpack(attr_code, attr_data)
                msg.rtup = stun_addr_field.tup

        # Set the additional IP and port for this server.
        if not hasattr(msg, "ctup"):
            if attr_code == STUNAttrs.ChangedAddress:
                stun_addr_field = STUNAddrTup(
                    af=af
                ).unpack(attr_code, attr_data)
                msg.ctup = stun_addr_field.tup
        
    return msg, buf

async def test_stun_utils():
    m = STUNMsg()
    buf = m.encode()

if __name__ == "__main__":
    async_test(test_stun_utils)