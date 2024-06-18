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

from .utils import *
from .stun_defs import *
from .net import *
from .ip_range import *
    
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
    msg.af = af
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
                ).unpack(attr_code, attr_data)
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

# Handles making a STUN request to a server.
# Pipe also accepts route and its upgraded to a pipe.
async def get_stun_reply(mode, dest_addr, reply_addr, pipe, attrs=[]):
    """
    The function uses subscriptions to the TXID so that even
    on unordered protocols like UDP the right reply is returned.
    The reply address forms part of that pattern which is an
    elegant way to validate responses from change requests
    which will otherwise timeout on incorrect addresses.
    """
    # Build the STUN message.
    msg = STUNMsg(mode=mode)
    for attr in attrs:
        attr_code, attr_data = attr
        msg.write_attr(attr_code, attr_data)

    # Subscribe to replies that match the req tran ID.
    sub = sub_to_stun_reply(msg.txn_id, reply_addr.tup)
    pipe.subscribe(sub)

    # Send the req and get a matching reply.
    send_buf = msg.pack()
    recv_buf = await send_recv_loop(dest_addr, pipe, send_buf, sub)
    log(f"stun reply {mode} {pipe.endpoint_type} {recv_buf}")
    if recv_buf is None:
        raise ErrorNoReply("STUN recv loop got no reply.")

    # Return response.
    reply, _ = stun_proto(recv_buf, reply_addr.af)
    reply.pipe = pipe
    reply.stup = reply_addr.tup
    return reply

async def stun_reply_to_ret_dic(reply):
    ret = {}
    if reply is None:
        return None

    if hasattr(reply, "ctup"):
        ret["cip"] = reply.ctup[0]
        ret["cport"] = reply.ctup[1]
    else:
        return None
    
    if hasattr(reply, "rtup"):
        ret["rip"] = reply.rtup[0]
        ret["rport"] = reply.rtup[1]
    else:
        return None
    
    if hasattr(reply, "stup"):
        ret["sip"] = reply.stup[0]
        ret["sport"] = reply.stup[1]
    else:
        return None
    
    if hasattr(reply, "pipe"):
        ltup = reply.pipe.sock.getsockname()[0:2]
        ret["lip"], ret["lport"] = ltup
    else:
        return None
    
    ret["resp"] = True
    return ret

def validate_stun_reply(reply, mode):
    if reply is None:
        log(f'{to_h(reply.txn_id)}: reply none')
        return None
    
    # Pipe needs to exist to check change addrs.
    if not hasattr(reply, "pipe"):
        log(f'{to_h(reply.txn_id)}: no pipe')
        return None
    
    # Reply addr is stup of the server.
    req_attrs = ["stup", "rtup"]
    extra_attrs = req_attrs[:]
    if mode == RFC3489:
        extra_attrs.append("ctup")

    # Check attrs exist in the reply.
    for req_attr in extra_attrs:
        if not hasattr(reply, req_attr):
            log(f'{to_h(reply.txn_id)}: no attr {req_attr}')
            return None

    # The follow tups should all have pub IPs.
    for req_attr in extra_attrs:
        tup_ip, tup_port = getattr(reply, req_attr)[:2]
        cidr = af_to_cidr(reply.af)
        ipr = IPRange(tup_ip, cidr=cidr)
        if ipr.is_private:
            log(f'{req_attr} {to_h(reply.txn_id)}: {tup_ip} priv')
            return None
        if not valid_port(tup_port):
            log(f'{req_attr} {to_h(reply.txn_id)}: {tup_port} bad')
            return None

    return reply
    # stup - reply addr
    # ltup .reply.pipe.sock.getsockname()
    # ctup -- change tup
    # rtup -- remove tup
    

async def test_stun_utils():
    m = STUNMsg()
    buf = m.encode()

if __name__ == "__main__":
    async_test(test_stun_utils)