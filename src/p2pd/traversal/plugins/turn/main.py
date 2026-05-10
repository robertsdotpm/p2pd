"""Traversal plugin that relays connections through a TURN server."""
import asyncio
from aionetiface import EXT_BIND, UDP, get_infra, fstr, log, log_p2p
from ...traversal_plugin import Plugin
from ...strategy_registry import register
from ....protocol.proto_defs import P2P_RELAY
from .proto import TURNMsg
from .turn_utils import get_first_working_turn_client, rendezvous_rank


@register(phase="relay")
class TURNPlugin(Plugin):
    """Traversal plugin that establishes a P2P connection via a TURN relay server."""

    name = "turn"
    transport = UDP
    # TURN is a public-relay mechanism only; only EXT_BIND combos make
    # sense. auto_combos won't generate NIC_BIND / LOOPBACK_BIND combos
    # for us. The historical "if route_type == NIC_BIND: return"
    # guard at the top of run() is no longer needed.
    route_types = (EXT_BIND,)
    # 60 s budget: get_first_working_turn_client walks the rendezvous-
    # ranked server list with a 6 s per-server cap (PER_SERVER_TIMEOUT
    # in turn_utils.py); ~8 server attempts (48 s) leaves ~12 s for
    # CreatePermission + relay-tup futures + post-allocate signaling
    # tail latency on slower OSes / network paths.
    conf = {"timeout": 60}
    proto_messages = (
        (TURNMsg, P2P_RELAY, 10),
    )

    @classmethod
    async def setup(cls, node):
        factory = TURNPluginFactory(node.msg_cb, node.node_id)
        node.resources.register(factory)
        return factory

    # Maximum number of server-renegotiation round trips before giving up.
    # Each round trip is one (initiator picks server, responder fails to
    # reach it, signals back) cycle. With a typical INFRA TURN list of 10
    # candidates this is generous -- 5 cycles can exclude up to 5 servers.
    MAX_RENEGOTIATIONS = 5

    def __init__(self):
        super().__init__()

        # Resolved by a second run() call on this same instance when the peer's
        # reply arrives, unblocking the first run() call that is awaiting it.
        self.ready = asyncio.Future()
        self.turn_clients = None
        self.msg_cb = None
        self.node_id = ""

        # Set of (host, port) tuples that have been attempted and failed
        # (or that the peer has excluded) for this plugin instance.
        # Renegotiation excludes these from candidate pools so we never
        # reattempt a known-bad server.
        self.tried_servers = set()
        self.renego_count = 0

    async def run(self, reply=None):
        """Allocate a TURN relay, exchange addresses with the peer, and establish the channel.

        Server selection is initiator-decides with renegotiation. Mirrors
        reverse_connect's "I tell you what to do" pattern but adds a back
        channel so the responder can refuse a server and ask the initiator
        to pick again.

          * Initiator (reply is None): walks rendezvous-ranked TURN
            servers via get_first_working_turn_client, allocates, then
            sends TURNMsg with server_host/server_port embedded so the
            responder allocates on the SAME server. tried_servers
            carries every server the initiator has already attempted
            (just the one chosen, on the first round).
          * Responder receives TURNMsg with a server_host: tries to
            allocate on that server. If reachable -> normal flow. If
            unreachable -> sends back a TURNMsg with reject_reason set
            and tried_servers including the rejected server. relay_tup
            in the rejection is None.
          * Initiator receives a rejection: merges tried_servers into
            its local set, drops the cached client, picks the next
            best server from rendezvous excluding the tried set,
            allocates fresh, and sends a new TURNMsg.

        The renegotiation is bounded by MAX_RENEGOTIATIONS to keep a
        broken pair from looping forever; after that budget is spent the
        session aborts cleanly. The previous behaviour -- one server
        choice, no recourse -- meant any case where the initiator's
        chosen server was reachable to it but not to the responder
        (e.g. initiator on a mobile carrier reaching a Chinese coturn
        the responder's home ISP can't) silently NO_ECHO'd.
        """
        is_initial_initiator = reply is None
        is_responder = reply is not None and not (
            getattr(reply.payload, "reject_reason", None)
        )
        is_renegotiating_initiator = (
            reply is not None and getattr(reply.payload, "reject_reason", None) is not None
        )
        role_label = (
            "responder" if is_responder
            else ("renego-initiator" if is_renegotiating_initiator else "initiator")
        )
        print("[TURN-DBG] run plugin_id={0} af={1} reply={2} role={3} renego_count={4} tried_servers_before={5}".format(
            self.plugin_id, self.af, reply is not None, role_label,
            self.renego_count, sorted(self.tried_servers),
        ))
        log(fstr(
            "turn[{0}]: run af={1} reply={2} role={3} renego_count={4}",
            (
                self.plugin_id, self.af, reply is not None,
                role_label, self.renego_count,
            ),
        ))

        # Merge any peer-supplied tried_servers into our local set so
        # neither side reattempts a server the other has already failed
        # on. Both rejection messages and normal TURNMsgs may carry
        # tried_servers; absorb either.
        if reply is not None:
            for s in (getattr(reply.payload, "tried_servers", None) or []):
                try:
                    self.tried_servers.add((s[0], int(s[1])))
                except (IndexError, TypeError, ValueError):
                    continue

        # --- Renegotiation initiator path ----------------------------------
        # The peer rejected our last server choice. Drop our cached client
        # (it was good for us but useless for them) and reallocate on a
        # different server. After MAX_RENEGOTIATIONS we give up.
        if is_renegotiating_initiator:
            self.renego_count += 1
            if self.renego_count > self.MAX_RENEGOTIATIONS:
                log(fstr(
                    "turn[{0}]: exceeded MAX_RENEGOTIATIONS ({1}); aborting",
                    (self.plugin_id, self.MAX_RENEGOTIATIONS),
                ))
                return
            print("[TURN-DBG] peer rejected our server reason={0!r} round={1}/{2} tried={3}".format(
                getattr(reply.payload, "reject_reason", None),
                self.renego_count, self.MAX_RENEGOTIATIONS,
                sorted(self.tried_servers),
            ))
            log(fstr(
                "turn[{0}]: peer rejected our server with reason={1}; "
                "renegotiating (round {2}/{3}, tried_servers={4})",
                (
                    self.plugin_id,
                    repr(getattr(reply.payload, "reject_reason", None)),
                    self.renego_count, self.MAX_RENEGOTIATIONS,
                    sorted(self.tried_servers),
                ),
            ))
            # The previous pick is now known-bad (peer couldn't reach it),
            # so add it to the failed set BEFORE re-picking. This is the
            # only place a successful-allocation server gets marked tried,
            # so the on-wire tried_servers list always means "rejected by
            # at least one peer", not "currently in use".
            existing = self.turn_clients.get(self.plugin_id)
            if existing is not None:
                try:
                    self.tried_servers.add((existing.dest[0], int(existing.dest[1])))
                except (IndexError, TypeError, ValueError):
                    pass
                try:
                    await existing.close()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log_p2p("turn[{0}]: error closing rejected client".format(self.plugin_id),
                            self.node_id[:8])
                del self.turn_clients[self.plugin_id]
            # From here on this branch behaves as a fresh initiator.
            reply = None

        # --- Allocate a TURN relay for this session ---
        client = self.turn_clients.get(self.plugin_id)
        print("[TURN-DBG] cached_client_present={0} for plugin_id={1}".format(
            client is not None, self.plugin_id,
        ))
        if client is None:
            groups = get_infra(self.af, UDP, "TURN", no=100)
            all_servers = [g[0] for g in groups]
            print("[TURN-DBG] infra returned {0} TURN groups for af={1}".format(
                len(all_servers), self.af,
            ))
            # Filter out any server already in the joint tried set.
            all_servers = [
                s for s in all_servers
                if (s.get("ip"), int(s.get("port", 0))) not in self.tried_servers
            ]
            print("[TURN-DBG] after tried-filter: {0} candidates remain".format(len(all_servers)))

            # Responder path: if the incoming TURNMsg specified a server
            # the initiator already allocated on, use it directly so we
            # land on the SAME server. If we cannot reach it, send a
            # rejection back instead of silently failing.
            chosen_servers = None
            initiator_choice = None
            if reply is not None and getattr(reply.payload, "server_host", None):
                target_host = reply.payload.server_host
                target_port = int(reply.payload.server_port or 0)
                initiator_choice = (target_host, target_port)
                for s in all_servers:
                    if s.get("ip") == target_host and int(s.get("port", 0)) == target_port:
                        chosen_servers = [s]
                        break
                # If we don't have it in INFRA, treat as unreachable too --
                # send rejection so the initiator picks something we share.
                if chosen_servers is None:
                    print("[TURN-DBG] initiator chose {0}:{1} not in our INFRA -> sending rejection (not_in_infra)".format(
                        target_host, target_port,
                    ))
                    log(fstr(
                        "turn[{0}]: initiator chose {1}:{2} but it's not in our "
                        "INFRA / already-tried; rejecting",
                        (self.plugin_id, target_host, target_port),
                    ))
                    self.tried_servers.add(initiator_choice)
                    await self._send_rejection("not_in_infra")
                    return

            if chosen_servers is None:
                chosen_servers = rendezvous_rank(self.plugin_id, all_servers)

            print("[TURN-DBG] trying {0} candidate server(s); first={1}".format(
                len(chosen_servers),
                (chosen_servers[0].get("ip"), chosen_servers[0].get("port")) if chosen_servers else None,
            ))
            log(fstr(
                "turn[{0}]: trying {1} candidate server(s)",
                (self.plugin_id, len(chosen_servers)),
            ))
            client = await get_first_working_turn_client(
                self.af,
                chosen_servers,
                self.nic,
                self.msg_cb,
            )
            print("[TURN-DBG] get_first_working_turn_client returned client={0} dest={1}".format(
                client is not None,
                getattr(client, "dest", None) if client is not None else None,
            ))

            if client is None:
                # If we are the responder and the initiator picked a
                # specific server, send a rejection so they retry. If
                # we're the initiator (or renego-initiator) and have no
                # working server left, abort.
                if initiator_choice is not None:
                    print("[TURN-DBG] failed to allocate on initiator's pick {0}:{1} -> sending rejection (unreachable)".format(
                        initiator_choice[0], initiator_choice[1],
                    ))
                    log(fstr(
                        "turn[{0}]: failed to allocate on initiator's server "
                        "{1}:{2}; sending rejection",
                        (self.plugin_id, initiator_choice[0], initiator_choice[1]),
                    ))
                    self.tried_servers.add(initiator_choice)
                    await self._send_rejection("unreachable")
                    return
                print("[TURN-DBG] no working TURN server -- aborting")
                log(fstr(
                    "turn[{0}]: no working TURN server -- aborting",
                    (self.plugin_id,),
                ))
                return
            print("[TURN-DBG] allocated relay on {0}".format(getattr(client, "dest", "?")))
            log(fstr(
                "turn[{0}]: allocated relay on {1}",
                (self.plugin_id, getattr(client, "dest", "?")),
            ))
            # NB: do NOT add the freshly-allocated server to self.tried_servers.
            # tried_servers means "rejected by at least one peer" -- it is shipped
            # to the peer so the peer's candidate filter excludes those entries.
            # Adding our successful pick here would cause the responder to
            # filter it out and reply "not_in_infra", looping until both
            # sides exhaust the list. The renego-initiator branch above is
            # the only place a successful pick gets marked tried, and only
            # AFTER we know the peer actually rejected it.

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
            print("[TURN-DBG] accept_peer dest_peer={0} dest_relay={1}".format(
                dest_peer, dest_relay,
            ))
            try:
                already_accepted = await asyncio.wait_for(
                    client.accept_peer(dest_peer, dest_relay), 30,
                )
            except asyncio.TimeoutError:
                print("[TURN-DBG] accept_peer timed out; sending rejection")
                await self._send_rejection("accept_peer_timeout")
                await self.close()
                return
            print("[TURN-DBG] accept_peer returned already_accepted={0}".format(already_accepted))

            # Unblock any initiating run() that is waiting for the peer's info.
            if not self.ready.done():
                print("[TURN-DBG] resolving self.ready (unblock the initiating run)")
                self.ready.set_result(client)

            # If both sides have already whitelisted each other, the relay
            # channel is fully established — nothing more to send.
            if already_accepted:
                print("[TURN-DBG] both sides whitelisted -> setting result, returning")
                if not self.result.done():
                    self.result.set_result(client)
                return

            our_relay = await client.relay_tup_future
            print("[TURN-DBG] our_relay={0} -- sending follow-up TURNMsg".format(our_relay))
            log_p2p(
                fstr(
                    "Whitelist {0} -> {1} to '{2}'",
                    (dest_peer, our_relay, self.nic.name),
                ),
                self.node_id[:8],
            )

        # --- Advertise our relay address (and server choice) to the peer ---
        # Embed the chosen server's host/port so the peer allocates on the
        # SAME server. tried_servers carries our local exclusion set so
        # the peer (whether responder, or initiator receiving our own
        # rejection-driven rechoice) never picks something we've already
        # ruled out. On the responder path (reply is not None) we pass
        # the same server back through, which is harmless -- the initiator
        # already used it. On the initiator path (reply is None) this is
        # how the responder learns which server to use.
        server_host, server_port = client.dest
        msg = TURNMsg(
            {
                "payload": {
                    "peer_tup": await client.client_tup_future,
                    "relay_tup": await client.relay_tup_future,
                    "server_host": server_host,
                    "server_port": server_port,
                    "tried_servers": [list(t) for t in sorted(self.tried_servers)],
                },
            }
        )
        msg.meta.plugin_name = "turn"
        print("[TURN-DBG] sending TURNMsg server={0}:{1} relay={2} tried={3}".format(
            server_host, server_port, msg.payload.relay_tup,
            [list(t) for t in sorted(self.tried_servers)],
        ))
        await self.send_signal(msg)
        print("[TURN-DBG] TURNMsg sent OK")

        # --- Wait for the peer to whitelist our relay ---
        # self.ready is resolved by a second run() call when the peer's reply
        # arrives. Cap at 40s: peer allocation + accept_peer takes at most
        # ~35s (6s alloc + 25s accept_peer max), plus signaling overhead.
        # Without this cap, a non-responding peer makes us burn the full
        # 60s plugin timeout at the initiator side.
        print("[TURN-DBG] awaiting self.ready (peer-whitelist barrier)")
        try:
            pipe = await asyncio.wait_for(self.ready, 40)
        except asyncio.TimeoutError:
            print("[TURN-DBG] self.ready timed out (peer never whitelisted)")
            return
        print("[TURN-DBG] self.ready resolved -> setting final result")
        if not self.result.done():
            self.result.set_result(pipe)

    async def _send_rejection(self, reason):
        """Tell the peer we cannot allocate on the server they just asked us
        to use. Carries our full tried_servers set so the peer's next pick
        excludes everything we've ruled out, not just the one server we
        rejected this round. relay_tup / peer_tup are filled with sentinel
        empty tuples because the on-wire schema requires them but the
        receiver ignores them when reject_reason is set."""
        msg = TURNMsg(
            {
                "payload": {
                    "peer_tup": ("", 0),
                    "relay_tup": ("", 0),
                    "tried_servers": [list(t) for t in sorted(self.tried_servers)],
                    "reject_reason": reason,
                },
            }
        )
        msg.meta.plugin_name = "turn"
        log(fstr(
            "turn[{0}]: sending rejection reason={1} tried={2}",
            (self.plugin_id, reason, sorted(self.tried_servers)),
        ))
        await self.send_signal(msg)

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
            # raises if pending, cancelled, or exception
            self.result.result()
            connection_succeeded = True
        except BaseException:
            pass

        if not connection_succeeded:
            # Per-run cleanup intentionally does NOT pop turn_clients
            # here. Cleanup semantics across plugins will be revisited
            # in a dedicated session; for now leave the entry so a
            # peer's follow-up signal doesn't trigger a duplicate
            # allocation while the original is still tearing down.
            turn_client = self.turn_clients.get(self.plugin_id)
            if turn_client is not None:
                await turn_client.close()

        if not self.ready.done():
            self.ready.cancel()


class TURNPluginFactory:
    """Creates and configures TURNPlugin instances sharing TURN client sessions."""

    def __init__(self, msg_cb=None, node_id=""):
        self.turn_clients = {}
        self.msg_cb = msg_cb
        self.node_id = node_id

    def build_plugin(self):
        """Create a new TURNPlugin instance wired to this factory's shared client pool."""
        plugin = TURNPlugin()
        plugin.turn_clients = self.turn_clients
        plugin.msg_cb = self.msg_cb
        plugin.node_id = self.node_id
        return plugin

    async def close(self):
        """Close all shared TURN clients and clear the pool."""
        for client in list(self.turn_clients.values()):
            try:
                await client.close()
            except (OSError, asyncio.TimeoutError):
                pass

        self.turn_clients.clear()


