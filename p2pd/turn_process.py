import asyncio
import io
from struct import unpack
from hashlib import md5
from .utils import *
from .address import *
from .turn_defs import *
from .stun_utils import *
from .pipe_client import *

# Parse a TURN message.
# Use bitwise OPs to get valid method and status codes.
def turn_parse_msg(buf):
    try:
        turn_msg, _ = STUNMsg.unpack(buf, mode=RFC5389)
        turn_method = b_and(turn_msg.msg_type, b"\x00\x0f")
        turn_status = b_and(turn_msg.msg_type, b"\x01\x10")
        return turn_msg, turn_method, turn_status
    except Exception:
        return None, None, None

"""
Messages sent to a relay address get returned by the TURN
server to the client as a message with a:
A) DATA attribute (the message)
B) Peer Address attribute (the sender)

Return this information to the caller.
"""
def turn_get_data_attr(msg, af, client):
    # Step through all attributes.
    data = peer_tup = None
    while not msg.eof():
        attr_code, _, attr_data = msg.read_attr()

        # The message segment.
        if attr_code == STUNAttrs.Data:
            if isinstance(attr_data, memoryview):
                data = attr_data.tobytes()
            else:
                data = attr_data

        # The sender of the message.
        if attr_code == STUNAttrs.XorPeerAddress:
            stun_addr = STUNAddrTup(
                af=af,
                txid=msg.txn_id,
                magic_cookie=msg.magic_cookie,
            )
            stun_addr.decode(attr_code, attr_data)
            peer_tup = stun_addr.tup

            # Validate the peer addr.
            ext = client.turn_pipe.route.ext()
            if peer_tup[0] == ext:
                error = f"""
                We received a TURN message from ourselves
                this might indicate bad logic
                msg peer_tup 0 == {ext}
                """
                log(error)

    # Reset attribute pointer to start.
    msg.attr_cursor = 0

    # Return results (if any.)
    return data, peer_tup

# True when all the fields in the client needed for auth are set.
def is_auth_ready(self):
    key_con = self.key is not None
    realm_con = self.realm is not None
    nonce_con = self.nonce is not None
    if key_con and realm_con and nonce_con:
        return True
    else:
        return False
    
def turn_proc_attrs(af, attr_code, attr_data, msg, self):
    error_code = 0
    error_msg = b''

    # Server address given back for relaying messages.
    if attr_code == STUNAttrs.XorRelayedAddress:
        if self.relay_tup is None:
            # Extract the relay address info to a tup.
            stun_addr = STUNAddrTup(
                af=af,
                txid=msg.txn_id,
                magic_cookie=msg.magic_cookie,
            )
            stun_addr.decode(attr_code, attr_data)
            self.relay_tup = stun_addr.tup

            # Indicate the tup has been set.
            self.relay_tup_future.set_result(self.relay_tup)
            log(f"> Turn setting relay addr = {self.relay_tup}")
            self.relay_event.set()

            # Validate relay tup IP.
            if self.relay_tup[0] != self.dest[0]:
                error = f"""
                Our XOR relay tup IP was decoded as 
                {self.relay_tup[0]} which is different 
                from the address of the TURN server 
                {self.dest[0]} which may 
                indicate a XOR decoding error.
                """
                log(error)

    # Handle authentication.
    if attr_code == STUNAttrs.Realm:
        self.realm = attr_data
        if self.turn_user is not None and self.turn_pw is not None:
            self.key = md5(self.turn_user + b':' + self.realm + b':' + self.turn_pw).digest()
            log("> Turn setting key = %s" % ( to_s(to_h(self.key)) ) )

    # Nonce is used for reply protection.
    # As our client uses a state-machine the impact of this is minimal.
    elif attr_code == STUNAttrs.Nonce:
        self.nonce = attr_data
        if IS_DEBUG:
            log("> Turn setting nonce = %s" % ( to_s(to_h(self.nonce.tobytes()))  ) )

    elif attr_code == STUNAttrs.Lifetime:
        self.lifetime, = unpack("!I", attr_data)
        if IS_DEBUG:
            log("> Turn setting lifetime = %d" % ( self.lifetime ))

    # Return any error codes.
    elif attr_code == STUNAttrs.ErrorCode:
        b2 = io.BytesIO(attr_data)
        d = b2.read(4)
        error_code = (d[2] & 0x7) * 100 + d[3]
        error_msg = b2.read()


    return [error_code, error_msg]

# Processes attributes from a TURN message.
async def process_attributes(af, self, msg):
    # Unpack attributes from message.
    error_code = 0
    error_msg = b''
    while not msg.eof():
        attr_code, _, attr_data = msg.read_attr()
        turn_proc_attrs(af, attr_code, attr_data, msg, self)
        stun_proc_attrs(af, attr_code, attr_data, msg)
        if hasattr(msg, "rtup"):
            if not len(self.mapped):
                self.mapped = msg.rtup
                self.client_tup_future.set_result(self.mapped)


    # Trigger auth ready event.
    if is_auth_ready(self):
        if not self.auth_event.is_set():
            self.auth_event.set()

    # Reset attribute pointer to start.
    msg.attr_cursor = 0

    # Return any errors info.
    return [error_code, error_msg]

# Process any replies from the TURN server.
# This function is run concurrently and doesn't block the main program.
async def process_replies(self):
    # Keep processing until stopped.
    while self.state != TURN_ERROR_STOPPED:
        # Prune old tasks.
        self.tasks = rm_done_tasks(self.tasks)

        # Async wait for up to N seconds for new messages.
        try:
            out = await self.turn_pipe.recv(timeout=1)
        except Exception:
            await asyncio.sleep(1)
            continue

        # Timeout no messages.
        if out is None:
            await asyncio.sleep(1)
            continue

        # Option B) Parse TURN messages from the server.
        turn_msg, turn_method, turn_status = turn_parse_msg(memoryview(out))
        if turn_msg is None:
            continue

        """
        Some TURN messages may have data attributes.
        These indicate a peer who sent data to our relay address.
        Attempt to look for these attributes and process them if found.
        """
        msg_data, peer_tup = turn_get_data_attr(turn_msg, self.turn_pipe.route.af, self)

        if msg_data is not None and peer_tup is not None:
            # Not a peer we white listed.
            peer_tup = norm_client_tup(peer_tup)
            if peer_tup not in self.peers:
                error = f"""
                Got a TURN data message from an 
                unknown peer = {peer_tup} which 
                may indicate a decoding error.
                """
                log(error)
                continue

            # Get relay address to route to sender of the message.
            peer_relay_tup = self.peers[peer_tup]

            # Tell the sender that we got the message.
            _, payload = self.stream.handle_ack(
                msg_data,
                self.stream.is_ack,
                self.stream.is_ackable,
                lambda buf: self.stream.send(buf, peer_relay_tup)
            )

            """
            A simple ACK-based protocol is transparently applied to the
            relay messages behind the scenes to add reliability.
            If the header can't be found then the original message
            will be unknown so we skip it.
            """
            if payload is None:
                log(f"Payload from turn was None but msg data = {msg_data}")
                if not self.blank_rudp_headers:
                    continue
                else:
                    self.handle_data(msg_data, peer_tup)
                    continue

            """
            The senders message has been stripped of the ACK header.
            It is then routed to this object (pipe-like object)
            where it will be handled and/or queued. The sender's
            relay address is listed as the sender to make it
            easy to route replies transparently.
            """
            self.handle_data(payload, peer_tup)
            continue
    
        """
        When a TURN message is sent it has a unique TXID.
        Replies in response to these messages use the same TXID.
        Unknown TXIDs for messages are discarded.
        """
        txid = turn_msg.txn_id
        if txid not in self.msgs:
            log("Got turn message with unknown TXID.")
            continue

        # A few important attributes are saved into the client for future use.
        # Mostly details for relaying and authentication.
        try:
            error_code, error_msg = await process_attributes(self.turn_pipe.route.af, self, turn_msg)
        except Exception:
            log_exception()
            continue

        # Log any error messages.
        if turn_status == STUNMsgCodes.ErrorResp:
            log('Turn error {}: {}'.format(error_code, error_msg))
            log(f"turn hex msg: {to_h(turn_msg.pack())}")

            # Stale nonce.
            if error_code == 438:
                log(f"stole nonce. retransmit for {txid}")
                self.msgs[txid]["status"].set_result(STATUS_RETRY)
                continue

        # Attempt to authenticate or create a relay address or refresh one.
        if turn_method == STUNMsgTypes.Allocate:
            log("got alloc")

            # Notify sender that message was received.
            self.msgs[txid]["status"].set_result(STATUS_SUCCESS)
            if turn_status == STUNMsgCodes.SuccessResp:
                if self.state != TURN_TRY_ALLOCATE:
                    #self.txid = txid
                    #self.requires_auth = False
                    self.auth_event.set()
            else:
                log("Error in TURN allocate")
                
            """
            The first 'allocate' message makes the server return attributes
            needed to authenticate and sign all future messages.
            Hence failing once is expected.
            """
            if turn_status == STUNMsgCodes.ErrorResp:
                # Avoid infinite loop of allocations.
                if self.state != TURN_TRY_ALLOCATE:
                    self.set_state(TURN_TRY_ALLOCATE)

                    # All future messages from here-on in are 'signed.'
                    task = asyncio.create_task(
                        async_retry(
                            lambda: self.allocate_relay(sign=True),
                            count=5
                        )
                    )
                    self.tasks.append(task)

            continue

        # White list a particular peer to send replies to our relay address.
        if turn_method == STUNMsgTypes.CreatePermission:
            if turn_status == STUNMsgCodes.SuccessResp:
                # Notify sender that message was received.
                self.msgs[txid]["status"].set_result(STATUS_SUCCESS)
            else:
                error = \
                f"Error in TURN create permission = "
                f"{to_h(turn_msg.pack())}"
                log(error)

            continue

        if turn_method == STUNMsgTypes.Refresh:
            self.msgs[txid]["status"].set_result(STATUS_SUCCESS)
            continue

    self.turn_client_stopped.set()
