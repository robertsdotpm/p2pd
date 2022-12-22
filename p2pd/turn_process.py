import asyncio
import io
from struct import unpack
from hashlib import md5
from .utils import *
from .address import *
from .turn_defs import *

# Parse a TURN message.
# Use bitwise OPs to get valid method and status codes.
def turn_parse_msg(buf):
    try:
        turn_msg, _ = TurnMessage.unpack(buf)
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
def turn_get_data_attr(msg, af):
    # Step through all attributes.
    data = peer_tup = None
    while not msg.eof():
        attr_code, _, attr_data = msg.read_attr()

        # The message segment.
        if attr_code == TurnAttribute.Data:
            if isinstance(attr_data, memoryview):
                data = attr_data.tobytes()
            else:
                data = attr_data

        # The sender of the message.
        if attr_code == TurnAttribute.XorPeerAddress:
            peer_tup = turn_peer_attr_to_tup(
                attr_data,
                msg.txn_id,
                af
            )

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

# Processes attributes from a TURN message.
async def process_attributes(self, msg):
    # Unpack attributes from message.
    error_code = 0
    error_msg = b''
    while not msg.eof():
        attr_code, _, attr_data = msg.read_attr()

        # Src port of UDP packet + external IP.
        # These details are XORed based on whether its IPv4 or IPv6.
        if attr_code == TurnAttribute.XorMappedAddress:
            if self.mapped != []:
                continue

            self.mapped = turn_peer_attr_to_tup(
                attr_data,
                self.txid,
                self.turn_addr.af
            )
            log("> Turn setting mapped address = {}".format(self.mapped))
            self.client_tup_future.set_result(self.mapped)

        # Server address given back for relaying messages.
        if attr_code == TurnAttribute.XorRelayedAddress:
            if self.relay_tup is not None:
                continue

            # Extract the relay address info to a tup.
            self.relay_tup = turn_peer_attr_to_tup(
                attr_data,
                self.txid,
                self.turn_addr.af
            )

            # Indicate the tup has been set.
            self.relay_tup_future.set_result(self.relay_tup)
            log(f"> Turn setting relay addr = {self.relay_tup}")
            self.relay_event.set()

        # Handle authentication.
        if attr_code == TurnAttribute.Realm:
            self.realm = attr_data
            if self.turn_user is not None and self.turn_pw is not None:
                self.key = md5(self.turn_user + b':' + self.realm + b':' + self.turn_pw).digest()
                log("> Turn setting key = %s" % ( to_s(to_h(self.key)) ) )

        # Nonce is used for reply protection.
        # As our client uses a state-machine the impact of this is minimal.
        elif attr_code == TurnAttribute.Nonce:
            self.nonce = attr_data
            if IS_DEBUG:
                log("> Turn setting nonce = %s" % ( to_s(to_h(self.nonce.tobytes()))  ) )

        elif attr_code == TurnAttribute.Lifetime:
            self.lifetime, = unpack("!I", attr_data)
            if IS_DEBUG:
                log("> Turn setting lifetime = %d" % ( self.lifetime ))

        # Return any error codes.
        elif attr_code == TurnAttribute.ErrorCode:
            b2 = io.BytesIO(attr_data)
            d = b2.read(4)
            error_code = (d[2] & 0x7) * 100 + d[3]
            error_msg = b2.read()

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
        msg_data, peer_tup = turn_get_data_attr(turn_msg, self.turn_addr.af)
        if msg_data is not None and peer_tup is not None:
            # Not a peer we white listed.
            peer_ip = peer_tup[0]
            if peer_ip not in self.peers:
                log("Got a message from an unknown peer.")
                continue

            # Get relay address to route to sender of the message.
            peer_relay_tup = self.peers[peer_ip]

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
                log(f"Payload from in turn was None {msg_data}")
                continue

            """
            The senders message has been stripped of the ACK header.
            It is then routed to this object (pipe-like object)
            where it will be handled and/or queued. The sender's
            relay address is listed as the sender to make it
            easy to route replies transparently.
            """
            self.handle_data(payload, peer_relay_tup)
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
            error_code, error_msg = await process_attributes(self, turn_msg)
        except Exception:
            log_exception()
            continue

        # Log any error messages.
        if turn_status == TurnMessageCode.ErrorResp:
            log('Turn error {}: {}'.format(error_code, error_msg))

            # Stale nonce.
            if error_code == 438:
                """
                The client looks for the MESSAGE-INTEGRITY attribute in the response
                (either success or failure).  If present, the client computes the
                message integrity over the response as defined in Section 15.4, using
                the same password it utilized for the request.  If the resulting
                value matches the contents of the MESSAGE-INTEGRITY attribute, the
                response is considered authenticated.  If the value does not match,
                or if MESSAGE-INTEGRITY was absent, the response MUST be discarded,
                as if it was never received.
                """
                log(f"stole nonce. retransmit for {txid}")
                self.msgs[txid]["status"].set_result(STATUS_RETRY)
                continue

        # Attempt to authenticate or create a relay address or refresh one.
        if turn_method == TurnMessageMethod.Allocate:
            log("got alloc")

            # Notify sender that message was received.
            self.msgs[txid]["status"].set_result(STATUS_SUCCESS)

            """
            The first 'allocate' message makes the server return attributes
            needed to authenticate and sign all future messages.
            Hence failing once is expected.
            """
            if turn_status == TurnMessageCode.ErrorResp:
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
        if turn_method == TurnMessageMethod.CreatePermission:
            if turn_status == TurnMessageCode.SuccessResp:
                # Notify sender that message was received.
                self.msgs[txid]["status"].set_result(STATUS_SUCCESS)

            continue

        if turn_method == TurnMessageMethod.Refresh:
            self.msgs[txid]["status"].set_result(STATUS_SUCCESS)
            continue

    self.turn_client_stopped.set()