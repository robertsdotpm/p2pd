"""Traversal plugin that relays connections through a TURN server."""
from typing import Any, Optional
import asyncio
from aionetiface import NIC_BIND, UDP, get_infra, fstr, log_p2p
from ...traversal_plugin import TraversalPlugin
from ....protocol.proto_msg import TURNMsg
from .turn_utils import get_first_working_turn_client, rendezvous_rank


class TURNPlugin(TraversalPlugin):
    """Traversal plugin that establishes a P2P connection via a TURN relay server."""

    def __init__(self) -> None:
        super().__init__()

        # Resolved by a second run() call on this same instance when the peer's
        # reply arrives, unblocking the first run() call that is awaiting it.
        self.ready = asyncio.Future()
        self.turn_clients = None
        self.msg_cb = None
        self.node_id = ""

    async def run(self, reply: Optional[Any] = None) -> None:
        """Allocate a TURN relay, exchange addresses with the peer, and establish the channel."""
        # TURN relay requires a public relay server; skip for direct NIC binds.
        if self.route_type == NIC_BIND:
            return

        # --- Allocate a TURN relay for this session ---
        # Both peers independently derive the same server ranking from the shared
        # plugin_id via rendezvous hashing, so no server-id exchange is needed.
        client = self.turn_clients.get(self.plugin_id)
        if client is None:
            groups = get_infra(self.af, UDP, "TURN", no=100)
            servers = rendezvous_rank(self.plugin_id, [g[0] for g in groups])
            client = await get_first_working_turn_client(
                self.af,
                servers,
                self.nic,
                self.msg_cb,
            )

            if client is None:
                return

            # A concurrent run() may have raced through the await above and
            # already stored a client — reuse it and discard ours.
            existing = self.turn_clients.get(self.plugin_id)
            if existing is not None:
                await client.close()
                client = existing
            else:
                self.turn_clients[self.plugin_id] = client

        if client is None:
            return

        # --- Accept the peer's relay (reply path only) ---
        # When the peer's TURNMsg arrives, whitelist their relay address so
        # the TURN server will forward their traffic to us.
        if reply is not None:
            dest_peer = reply.payload.peer_tup
            dest_relay = reply.payload.relay_tup
            already_accepted = await client.accept_peer(dest_peer, dest_relay)

            # Unblock any initiating run() that is waiting for the peer's info.
            if not self.ready.done():
                self.ready.set_result(client)

            # If both sides have already whitelisted each other, the relay
            # channel is fully established — nothing more to send.
            if already_accepted:
                if not self.result.done():
                    self.result.set_result(client)
                return

            our_relay = await client.relay_tup_future
            log_p2p(
                fstr(
                    "Whitelist {0} -> {1} to '{2}'",
                    (dest_peer, our_relay, self.nic.name),
                ),
                self.node_id[:8],
            )

        # --- Advertise our relay address to the peer ---
        msg = TURNMsg(
            {
                "payload": {
                    "peer_tup": await client.client_tup_future,
                    "relay_tup": await client.relay_tup_future,
                },
            }
        )
        msg.meta.plugin_name = "turn"
        await self.send_signal_msg(msg)

        # --- Wait for the peer to whitelist our relay ---
        # self.ready is resolved by a second run() call when the peer's reply arrives.
        pipe = await self.ready
        if not self.result.done():
            self.result.set_result(pipe)

    async def close(self) -> None:
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
            # raises if pending, cancelled, or exception
            self.result.result()
            connection_succeeded = True
        except BaseException:
            pass

        if not connection_succeeded:
            turn_client = self.turn_clients.pop(self.plugin_id, None)
            if turn_client is not None:
                await turn_client.close()

        if not self.ready.done():
            self.ready.cancel()


class TURNPluginFactory:
    """Creates and configures TURNPlugin instances sharing TURN client sessions."""

    def __init__(self, msg_cb: Optional[Any] = None, node_id: str = "") -> None:
        self.turn_clients = {}
        self.msg_cb = msg_cb
        self.node_id = node_id

    def build_plugin(self) -> TURNPlugin:
        """Create a new TURNPlugin instance wired to this factory's shared client pool."""
        plugin = TURNPlugin()
        plugin.turn_clients = self.turn_clients
        plugin.msg_cb = self.msg_cb
        plugin.node_id = self.node_id
        return plugin

    async def close(self) -> None:
        """Close all shared TURN clients and clear the pool."""
        for client in list(self.turn_clients.values()):
            try:
                await client.close()
            except (OSError, asyncio.TimeoutError):
                pass

        self.turn_clients.clear()


# Total budget the traversal manager gives this plugin's run() call.
# get_first_working_turn_client walks the rendezvous-ranked server list
# with a 6s per-server cap (PER_SERVER_TIMEOUT in turn_utils.py); we
# need enough headroom here to absorb several bad-server fall-throughs
# before reaching a working relay PLUS the CreatePermission round-trip
# and the relay-tup futures. ~8 server attempts (48s) leaves ~12s for
# the post-allocate signaling exchange and tail latency on slower
# OSes / network paths.
PLUGIN_CONF = {"timeout": 60}


async def setup_plugin(node):
    """Create the TURN factory and register it for cleanup."""
    factory = TURNPluginFactory(node.msg_cb, node.node_id)
    node.resources.register(factory)
    return factory
