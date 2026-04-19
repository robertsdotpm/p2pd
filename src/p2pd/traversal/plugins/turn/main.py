import asyncio
from aionetiface import *
from ...traversal_plugin import TraversalPlugin
from ....protocol.traversal.proto_msg import TURNMsg
from .turn_utils import get_first_working_turn_client, rendezvous_rank


class TURNPlugin(TraversalPlugin):
    def __init__(self):
        super().__init__()
        # Resolved by a second run() call on this same instance when the peer's
        # reply arrives, unblocking the first run() call that is awaiting it.
        self.ready = asyncio.Future()

    async def run(self, reply=None):
        if self.route_type == NIC_BIND:
            return

        # Get or create TURN client for this plugin.
        if self.plugin_id in self.turn_clients:
            client = self.turn_clients[self.plugin_id]
        else:
            # Both sides derive the same server ranking from the shared plugin_id
            # via rendezvous hashing — no serv_id exchange needed.
            groups = get_infra(self.af, UDP, "TURN", no=100)
            servers = rendezvous_rank(self.plugin_id, [g[0] for g in groups])
            client = await get_first_working_turn_client(
                self.af,
                servers,
                self.nic,
                self.msg_cb,
            )

            # Guard against a concurrent run() that raced through the above
            # and already stored a client — reuse that one, discard ours.
            existing = self.turn_clients.get(self.plugin_id)
            if existing is not None:
                await client.close()
                client = existing
            else:
                self.turn_clients[self.plugin_id] = client

        # Process a reply carrying the remote peer's TURN relay info.
        if reply is not None:
            dest_peer = reply.payload.peer_tup
            dest_relay = reply.payload.relay_tup
            already_accepted = await client.accept_peer(dest_peer, dest_relay)

            if not self.ready.done():
                self.ready.set_result(client)

            if already_accepted:
                if not self.result.done():
                    self.result.set_result(client)
                return

            our_relay = await client.relay_tup_future
            log_p2p(
                fstr("Whitelist {0} -> {1} to '{2}'", (dest_peer, our_relay, self.nic.name)),
                self.node_id[:8],
            )

        # Build and send our TURN signaling message.
        msg = TURNMsg({
            "payload": {
                "peer_tup": await client.client_tup_future,
                "relay_tup": await client.relay_tup_future,
            },
        })
        msg.meta.plugin_name = "turn"
        await self.send_signal_msg(msg)

        # Wait for the remote side to whitelist us.
        pipe = await self.ready
        if not self.result.done():
            self.result.set_result(pipe)

    async def close(self):
        """Clean up after a TURN connection attempt.

        On failure (timeout, cancellation, error) the TURNClient is closed
        immediately to free the UDP socket, the relay allocation, and all
        background tasks.  On success the TURNClient *is* the pipe returned
        to the caller — the caller owns it and will close it — so we leave
        it open and let TURNPluginFactory.close() handle final shutdown.

        Safe to call multiple times: the dict pop is a no-op on a missing key
        and all futures are checked with .done() before acting.
        """
        connection_succeeded = False
        try:
            self.result.result()   # raises if pending, cancelled, or exception
            connection_succeeded = True
        except Exception:
            pass

        if not connection_succeeded:
            turn_client = self.turn_clients.pop(self.plugin_id, None)
            if turn_client is not None:
                await turn_client.close()

        if not self.ready.done():
            self.ready.cancel()
        if not self.result.done():
            self.result.cancel()


class TURNPluginFactory:
    def __init__(self, msg_cb=None, node_id=""):
        self.turn_clients = {}
        self.msg_cb = msg_cb
        self.node_id = node_id

    def build_plugin(self):
        plugin = TURNPlugin()
        plugin.turn_clients = self.turn_clients
        plugin.msg_cb = self.msg_cb
        plugin.node_id = self.node_id
        return plugin

    async def close(self):
        for client in list(self.turn_clients.values()):
            try:
                await client.close()
            except Exception:
                pass
        self.turn_clients.clear()
