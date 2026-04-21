
"""
TURN client using UDP (RFC 5766).

TURN's TCP connect mode assumes the destination is reachable, which makes
it useless for P2P — if a peer were reachable directly, there would be no
reason to use TURN in the first place. UDP is used instead: any outbound
UDP packet automatically opens a hole in the local NAT, making the client
reachable via the relay address.

Key differences from a standard TURN library:
  - UDP only (no TCP relay mode)
  - Multi-interface and IPv6 support
  - Multiple simultaneous client sessions
  - Full Pipe object compatibility

TODO: implement shared-secret authentication (currently uses static credentials)
"""

import asyncio
from struct import pack
from aionetiface import *
from .turn_process import *
from .turn_defs import *

# Main class for handling TURN sessions with a server.
class TURNClient(PipeEvents):
    def __init__(
        self,
        af,
        dest,
        nic,
        auth=("", ""),
        realm=None,
        msg_cb=None,
        conf=NET_CONF
    ):
        # Can received relay messages have a blank header?
        self.blank_rudp_headers = False

        # Remote address for the TURN server.
        # Username and password are optional.
        self.requires_auth = True
        self.af = af
        self.dest = dest
        self.turn_user = to_b(auth[0])
        self.turn_pw = to_b(auth[1])
        self.msg_cb = msg_cb

        # Set from attributes in replies.
        self.realm = realm
        if realm is not None:
            self.realm = to_b(realm)
        self.key = None
        self.nonce = None

        # The main UDP endpoint used to talk to the client.
        # route = NIC bind details to use for the pipe.
        self.turn_pipe = None
        self.nic = nic
        self.conf = conf

        # Special attribute set to indicate expiry time of an allocation.
        self.lifetime = TURN_REFRESH_EXPIRY

        # Our own peer address.
        self.mapped = []
        self.relay_tup = None

        # The initial session is associated with a random TXID.
        # Replies specify that TXID so the same session can be identified.
        self.txid = b""
        self.con_id = None

        # Event set when protocol completed and chan messages can be sent.
        self.processing_loop_task = None

        # The protocol client uses a state machine.
        # Each state has a set duration for it to be completed in.
        self.state_timestamp = timestamp()
        self.state = TURN_NOT_STARTED
        self.peers = {}
        self.msgs = {}
        self.tasks = []

        # Futures to return from start.
        self.turn_client_stopped = asyncio.Event()
        self.client_tup_future = asyncio.futures.Future()
        self.relay_tup_future = asyncio.futures.Future()
        self.auth_event = asyncio.Event()
        self.relay_event = asyncio.Event()
        self.node_events = {} # by node_id

    def get_turn_server(self, af=None):
        return {
            "host": self.dest[0],
            "port": self.dest[1],
            "afs": [af],
            "user": self.turn_user,
            "pass": self.turn_pw,
            "realm": self.realm
        }
    
    def get_relay_tup(self, peer_tup):
        if peer_tup in self.peers:
            return self.peers[peer_tup]
        else:
            return None

    def toggle_blank_rudp_headers(self, val):
        self.blank_rudp_headers = val

    # Make this whole clas look like a 'pipe' object.
    def super_init(self,  transport, sock, route, conf=NET_CONF):
        super().__init__(sock=sock, route=route, conf=conf)
        self.connection_made(transport)
        self.stream.set_handle(transport, client_tup=None)

    # Start the TURN client.
    async def start(self, n=0):
        # Set and validate peer address.
        log("> Turn starting client.")
        if self.turn_user is None and self.turn_pw is None:
            self.auth_event.set()

        # Connect to TURN server over UDP.
        self.dest = await resolv_dest(self.af, self.dest, self.nic)
        self.route = await self.nic.route(self.af).bind()
        try:
            self.turn_pipe = await Pipe(UDP, self.dest, self.route).connect()
            log(fstr("> Turn socket = {0}", (self.turn_pipe.sock,)))
        except (OSError, ConnectionError):
            log_exception()
            self.turn_pipe = None

        # If con was unncessessful raise exception.
        if self.turn_pipe is None:
            raise Exception("Unable to connect to TURN host. This may mean the server is no longer working. Normally TURN is not a public service.")

        # Subscribe to all messages.
        self.turn_pipe.subscribe(SUB_ALL)

        # Make this entire class shadow the pipe above.
        self.super_init(
            transport=self.turn_pipe.transport,
            sock=self.turn_pipe.sock,
            route=self.route,
            conf=self.conf
        )
        # super_init calls PipeEvents.__init__ which resets proto to None;
        # restore it so PipeClient.send() takes the UDP sendto() path.
        self.proto = UDP

        # Start processing UDP replies.
        self.processing_loop_task = asyncio.create_task(
            async_wrap_errors(
                process_replies(self)
            )
        )
        self.tasks.append(self.processing_loop_task)
        
        # Add any message handlers.
        if self.msg_cb is not None:
            self.add_msg_cb(self.msg_cb)

        # expect 'Unauthorized'.
        await async_retry(lambda: self.allocate_relay(sign=False), count=5)
        log(fstr("Turn expect unauth success"))

        # Wait for client to be ready.
        await self.auth_event.wait() # Authentication success.
        log(fstr("Turn auth success"))
        await self.relay_event.wait() # Our relay address available.
        log(fstr("Turn relay event success"))

        # Return our relay tup.
        relay_tup = await self.relay_tup_future
        log(fstr("Turn tup future success"))
        client_tup = await self.client_tup_future
        log(fstr("Turn client tup success"))

        # TODO: white-list ourselves if self-send support is ever needed.
        # await self.accept_peer(client_tup, relay_tup)

        # Refresh allocations.
        async def refresher():
            while True:
                await asyncio.sleep(TURN_REFRESH_EXPIRY - 60)
                try:
                    await async_retry(
                        lambda: self.refresh_allocation(),
                        count=5,
                        timeout=5
                    )
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    try:
                        await self.reconnect(n=1)
                    except (OSError, ConnectionError, asyncio.TimeoutError):
                        log_exception()
                        continue

        # First run of this function.
        if not n:
            self.allocate_refresher_task = asyncio.create_task(
                async_wrap_errors(
                    refresher()
                )
            )
            self.tasks.append(self.allocate_refresher_task)

        return self

    async def get_tups(self):
        client_tup = await self.client_tup_future
        relay_tup = await self.relay_tup_future
        return client_tup, relay_tup

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *_):
        await self.close()
        return False

    def __await__(self):
        return self.start().__await__()

    async def reconnect(self, n=0):
        await self.close()

        # Snapshot state before __init__ wipes it.
        af       = self.af
        dest     = self.dest
        nic      = self.nic
        auth     = (to_s(self.turn_user), to_s(self.turn_pw))
        realm    = to_s(self.realm) if self.realm is not None else None
        msg_cb   = self.msg_cb
        conf     = self.conf

        # Re-initialise with the correct positional/keyword signature.
        self.__init__(
            af=af,
            dest=dest,
            nic=nic,
            auth=auth,
            realm=realm,
            msg_cb=msg_cb,
            conf=conf,
        )

        # Try start it again.
        await self.start(n)

    # Changes the protocol state machine.
    def set_state(self, state):
        log("> Turn moving state from %s to %s." % (self.state, state))
        self.state = state

    def new_node_event(self, node_id):
        self.node_events[to_s(node_id)] = asyncio.Event()

    def get_first_peer_tup(self):
        for peer_tup in self.peers:
            return self.peers[peer_tup]

        return None

    # Overwrite the BaseProto send method and require ACKs.
    async def send(self, data, dest_tup=None):
        # Attempt to use the first peer_tup.
        if dest_tup is None:
            dest_tup = self.get_first_peer_tup()

        # Normalize IPv6 addresses (compressed → expanded) so that lookups
        # into self.peers — which stores keys via accept_peer/norm_client_tup —
        # succeed regardless of the form the caller passes in.
        if dest_tup is not None:
            dest_tup = norm_client_tup(dest_tup)

        # Detect invalid self-send.
        if self.relay_tup_future.done():
            relay_tup = await self.relay_tup_future
            if dest_tup == relay_tup:
                raise Exception("Coturn doesn't support self-send.")
            
        # Use a peers relay to reach them instead.
        if dest_tup in self.peers:
            dest_tup = tuple(self.peers[dest_tup])

        # Sanity checking.
        found_relay = False
        for peer_tup in self.peers:
            if self.peers[peer_tup] == dest_tup:
                found_relay = True
                break
        if not found_relay:
            log(fstr(
                "TURN.send(): dest_tup {0} does not match any accepted peer relay — "
                "possibly an invalid send address.",
                (dest_tup,)
            ))

        assert(type(dest_tup) == tuple)

        # Sanity checking on the dest IP.
        # If dest IP doesn't match this TURN server IP
        # it means maybe the wrong relay IP is used.
        if dest_tup[0] != self.dest[0]:
            log(fstr(
                "TURN.send(): dest IP {0} differs from server IP {1} — "
                "possibly a peer address or mixed relay servers.",
                (dest_tup[0], self.dest[0],)
            ))

        # Queue the send as a background task so the caller doesn't block.
        task = asyncio.create_task(
            async_wrap_errors(
                self.stream.ack_send(
                    data,
                    dest_tup
                )
            )
        )
        self.tasks.append(task)

    async def recv(self, sub=SUB_ALL, timeout=2):
        # Build a sub from the first accepted peer.
        if sub == SUB_ALL:
            sub = None
            
        if sub is None:
            for peer_tup in self.peers:
                sub = (b"", peer_tup)
                break

        assert(sub is not None)
        return await super().recv(sub, timeout)

    # Handles writing TURN messages to self.udp_stream.
    # Will write credential and HMAC if a message needs 'signing.'
    async def send_turn_msg(self, msg: STUNMsg, do_sign=False):
        buf, _ = STUNMsg.unpack(msg.pack(), mode=RFC5389)
        if self.requires_auth:
            if do_sign and self.key:
                buf.write_credential(self.turn_user, self.realm, self.nonce)
                buf.write_hmac(self.key)

        buf = buf.pack()
        await self.turn_pipe.send(buf, self.dest)

    # Record TURN protocol messages by TXID.
    # Events are triggered on receipt.
    def record_msg(self, msg):
        f = asyncio.Future()
        self.msgs[msg.txn_id] = {
            "status": f,
            "timestamp": timestamp(),
            "msg": msg
        }

        def new_future():
            a_future = asyncio.Future()
            self.msgs[msg.txn_id]["status"] = a_future
            return a_future

        def closure():
            async def retransmit():
                await self.send_turn_msg(msg, do_sign=True)

            return retransmit

        return f, closure(), new_future

    # Create and send an allocation request.
    # Results in a new relay address being allocated for the client.
    async def allocate_relay(self, sign):
        msg = await self.allocate_msg()
        f, retransmit, new_future = self.record_msg(msg)
        await self.send_turn_msg(msg, do_sign=sign)
        return f, retransmit, new_future

    # Create and send a create permission for a peers address.
    # Retry up to 3 times if no response to the packet.
    # Allows a peer to send messages to our relay address.
    async def accept_peer(self, peer_tup, peer_relay_tup):
        # Fixed 'compressed' IPv6 addresses.
        peer_tup = norm_client_tup(peer_tup)

        # Basic validation for logging.
        if peer_relay_tup[0] != self.dest[0]:
            log(fstr(
                "TURN accept_peer: relay IP {0} != server IP {1} — "
                "possible error or mixed TURN servers.",
                (peer_relay_tup[0], self.dest[0],)
            ))

        peer_tup = tuple(peer_tup)
        peer_relay_tup = tuple(peer_relay_tup)
        already_accepted = peer_tup in self.peers
        async def handler(peer_tup, peer_relay_tup):
            # Generate message to send.
            msg = await self.white_list_msg(peer_tup)
            self.peers[peer_tup] = peer_relay_tup

            # Send message to turn server.
            f, retransmit, new_future = self.record_msg(msg)
            return f, retransmit, new_future

        # Refresh permissions.
        f = lambda: handler(peer_tup, peer_relay_tup)
        async def refresher():
            while self.state != TURN_ERROR_STOPPED:
                await asyncio.sleep(TURN_REFRESH_EXPIRY - 60)
                await async_retry(f, count=5, timeout=5)
                log("Refresh permission.")

        # Prevent garbage collection.
        if not already_accepted:
            # Allow messages to be queued.
            sub = tup_to_sub(peer_tup)
            self.subscribe(sub)

            # White list the peer if needed.
            await async_retry(f, count=5, timeout=5)

            # Start the loop to refresh the permission.
            task = asyncio.create_task(
                async_wrap_errors(
                    refresher()
                )
            )
            self.tasks.append(task)

        return already_accepted

    # Relay addresses are only valid for a certain 'life time.'
    # This creates and sends a message to refresh the lifetime.
    async def refresh_allocation(self):
        log("> Turn refreshing allocate lifetime.")
        msg = await self.refresh_msg()
        f, retransmit, new_future = self.record_msg(msg)
        return f, retransmit, new_future
        
    # Main step 1 -- allocate a relay address msg.
    async def allocate_msg(self):
        reply = STUNMsg(
            msg_type=STUNMsgTypes.Allocate,
            mode=RFC5389
        )
        reply.write_attr(
            STUNAttrs.RequestedTransport,
            TURN_RPOTOCOL_UDP
        )

        self.txid = reply.txn_id
        return reply
        
    # Main step 2 -- white list a peer to use our relay address msg.
    # Apparently the port number is irrelevant.
    # Permissions are made per IP.
    async def white_list_msg(self, src_tup):        
        # Try write the peer address.
        reply = STUNMsg(
            msg_type=STUNMsgTypes.CreatePermission,
            mode=RFC5389
        )

        af = af_from_ip_s(src_tup[0])
        attr_code = STUNAttrs.XorPeerAddress
        attr_data = STUNAddrTup(
            ip=src_tup[0],
            port=src_tup[1],
            af=af,
            txid=reply.txn_id,
            magic_cookie=reply.magic_cookie,
        )
        reply.write_attr(attr_code, attr_data)

        # Some validation on address encoding.
        attr_data.tup = None
        attr_data.decode(attr_code, attr_data.encode(attr_code))
        if attr_data.tup != src_tup:
            error = fstr("""
            The decode of the white listed 
            peer addr in TURN did not match the src tup 
            this might indicate an encoding error 
            {0} != {1}""", (src_tup, attr_data.tup,))
            log(error)

        return reply

    # Step 3 - refresh allocation to avoid lifetime timeouts.
    async def refresh_msg(self):
        # 32 bit unsigned int
        reply = STUNMsg(
            msg_type=STUNMsgTypes.Refresh,
            mode=RFC5389
        )
        reply.write_attr(
            STUNAttrs.Lifetime,
            pack("!I", TURN_REFRESH_EXPIRY)
        )

        """
        reply.write_attr(
            TurnAttribute.RequestedTransport,
            TURN_RPOTOCOL_UDP
        )
        """

        # Return reply message.
        #reply.txn_id = self.txid
        return reply

    # Close the client socket and move state to done.
    async def do_cleanup(self):
        if self.turn_pipe is not None:
            await self.turn_pipe.close()

        # Make the main message process loop end.
        self.state = TURN_ERROR_STOPPED

        # Make pending TURN handlers finish.
        if not self.client_tup_future.done():
            self.client_tup_future.set_result((0, 0))

        if not self.relay_tup_future.done():
            self.relay_tup_future.set_result((0, 0))

        # Make any pending send or recv calls finish.
        self.auth_event.set()
        self.relay_event.set()

    async def close(self):
        # Already closed.
        if self.turn_client_stopped.is_set():
            return

        # Close all pipes.
        # Set events as done so all tasks end.
        await self.do_cleanup()

        # Processing loop sets this when done.
        await self.turn_client_stopped.wait()

        # Wait for permission refresher tasks or cancel them.
        await gather_or_cancel(self.tasks, 2)

if __name__ == '__main__': # pragma: no cover
    """
    // If left out, will use openrelay public TURN servers from metered.ca
    see if these servers work?
    turnIceServers: { ... },
    """
    async def test_turn():
        """
        buf = b"ur\x00\t\xd6o'\x04\x9ezp*\x01"
        m = TurnMessage.unpack(buf)[0]
        print(m)
        print(m.eof())
        while not m.eof():
            attr_code, _, attr_data = m.read_attr()
            attr_name = TurnAttribute.get(attr_code)

            print(attr_code)
            print(attr_name)

        return
        """
        interface = await Interface("enp1s0f0").start()
        af = AF_INET
        turn_user=b""
        turn_pw=b""
        route = interface.route(af)
        turn_addr = ("", 3478)


        """
        A faulty network interface will cause hosts with multiple
        interfaces to report non-deterministic results with defaults.
        Thus, its better to manually select an interface for testing
        than to silently fail and wonder what is going wrong.
        This interface uses a preserving type nat so it bypasses the
        issue with coturn reply ports.
        """
        client1 = TURNClient(
            turn_addr=turn_addr,
            turn_user=turn_user,
            turn_pw=turn_pw,
            interface=interface
        )

        client_tup_future, relay_tup_future, in_chan_event = await client1.start()
        client_tup = await client_tup_future
        relay_tup = await relay_tup_future

        """
        reply = TurnMessage(msg_type=TurnMessageMethod.Send, msg_code=TurnMessageCode.Indication)
        reply.write_attr(
            TurnAttribute.Data,
            b"send indication test msg."
        )
        turn_write_peer_addr(reply, client_tup)
        await client1.send_turn_msg(reply, do_sign=True)
        """


        while True:
            await asyncio.sleep(1)


    async_test(test_turn)


