import asyncio
from aionetiface import *
from ...traversal_plugin import TraversalPlugin
from ....protocol.traversal.proto_msg import TURNMsg
from .turn_utils import get_first_working_turn_client


class TURNPlugin(TraversalPlugin):
    async def run(self, reply=None):
        if self.route_type == NIC_BIND:
            return

        # Get or create TURN client for this pipe.
        if self.pipe_id in self.turn_clients:
            client = self.turn_clients[self.pipe_id]
        else:
            # On a reply, prefer the server the remote side already picked.
            offsets = list(range(0, len(TURN_SERVERS)))
            random.shuffle(offsets)
            if reply is not None:
                offsets = [reply.payload.serv_id]

            client = await get_first_working_turn_client(
                self.af,
                offsets,
                self.nic,
                self.msg_cb,
            )

            # Guard against a concurrent run() that raced through the above
            # and already stored a client — reuse that one, discard ours.
            existing = self.turn_clients.get(self.pipe_id)
            if existing is not None:
                await client.close()
                client = existing
            else:
                self.turn_clients[self.pipe_id] = client

        # Process a reply carrying the remote peer's TURN relay info.
        if reply is not None:
            dest_peer = reply.payload.peer_tup
            dest_relay = reply.payload.relay_tup
            already_accepted = await client.accept_peer(dest_peer, dest_relay)

            # Unblock any local waiter for this pipe.
            self._resolve_pipe(client)

            if already_accepted:
                # Both sides have already whitelisted each other; we're done.
                if not self.result.done():
                    self.result.set_result(client)
                return

            # Log the whitelist action before sending our own relay info back.
            our_relay = await client.relay_tup_future
            log_p2p(
                fstr("Whitelist {0} -> {1} to '{2}'", (dest_peer, our_relay, self.nic.name)),
                self.node_id[:8],
            )

        # Register the pipe future *before* sending so the reply handler can
        # resolve it even if the reply arrives before we reach the await below.
        if self.pipe_id not in self.pipes:
            self.pipes[self.pipe_id] = asyncio.Future()

        # Build and send our TURN signaling message.
        msg = TURNMsg({
            "payload": {
                "peer_tup": await client.client_tup_future,
                "relay_tup": await client.relay_tup_future,
                "serv_id": client.serv_offset,
            },
        })
        msg.meta.plugin_name = "turn"
        await self.signal_msg_sender(msg)

        # Wait for the remote side to whitelist us (resolved via _resolve_pipe
        # in a future run() call that carries the peer's reply).
        pipe = await self.pipes[self.pipe_id]
        if not self.result.done():
            self.result.set_result(pipe)

    def _resolve_pipe(self, client):
        """Resolve the shared pipe future so any concurrent waiter is unblocked."""
        future = self.pipes.get(self.pipe_id)
        if future is not None and not future.done():
            future.set_result(client)


class TURNPluginFactory:
    def __init__(self, turn_clients, msg_cb=None, node_id=""):
        self.turn_clients = turn_clients
        self.msg_cb = msg_cb
        self.node_id = node_id

    def build_plugin(self):
        plugin = TURNPlugin()
        plugin.turn_clients = self.turn_clients
        plugin.msg_cb = self.msg_cb
        plugin.node_id = self.node_id
        return plugin


async def turn_cleanup(plugin):
    """Remove and close the TURN client associated with a plugin."""
    turn_client = plugin.turn_clients.pop(plugin.pipe_id, None)
    if turn_client is None:
        return
    await turn_client.close()
