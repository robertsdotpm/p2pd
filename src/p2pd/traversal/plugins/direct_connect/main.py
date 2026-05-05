"""Traversal plugin for direct (non-NATed) connections."""
from typing import Any, List, Optional, Tuple
import asyncio
from aionetiface import IP4, IP6, Interface, TCP, Pipe, log, log_exception, fstr, to_b
from aionetiface.net.bind.bind_utils import patch_connect_ip
from ...traversal_plugin import TraversalPlugin
from .con_id_frame import CON_ID_PREFIX


def is_loopback_dest_str(s: str, af: Any) -> bool:
    """True iff the dest IP string is in loopback range for its AF."""
    if af == IP4:
        return s.startswith("127.")
    if af == IP6:
        return s == "::1" or s.startswith("::1")
    return False


def loopback_dest_candidates(plugin: Any, primary_dest: Tuple[str, int]) -> List[Tuple[str, int]]:
    """Return ordered (ip, port) candidates for the loopback connect path.

    The peer's addr_info carries enrich_addr_map_with_loopback's full
    candidate list (per-pubkey 127.X.Y.Z, 127.0.0.1:port, ::1:port,
    127.0.0.1:fallback_port). Filter to the plugin's AF and dedupe so
    DirectConnect can walk them in order on connect failure -- crucial
    for platforms (Windows XP) whose stack doesn't route the full
    127.0.0.0/8 block but does handle 127.0.0.1.
    """
    out = [primary_dest]
    seen = {primary_dest}
    candidates = plugin.dest_info.get("loopback_candidates") or []
    for cand_af, cand_ip, cand_port in candidates:
        if cand_af != plugin.af:
            continue
        key = (cand_ip, cand_port)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def loopback_src_for(plugin: Any) -> Optional[str]:
    """Return alice's own loopback alias (str) for binding the connect socket."""
    src_lo = plugin.src_info.get("loopback") if plugin.src_info else None
    if src_lo is None:
        return None
    return str(src_lo)


class DirectConnect(TraversalPlugin):
    """Traversal plugin that attempts a straightforward TCP connection to the peer."""

    async def run(self, reply: Optional[Any] = None) -> None:
        """Open a direct TCP connection to the peer and store the resulting pipe."""
        # Connect to this address. For v6 link-local destinations the
        # connect needs OUR local outgoing interface's scope_id appended
        # (the remote's scope_id is meaningless on our side -- scope_id
        # tells our kernel which physical NIC to send the SYN out of).
        # patch_connect_ip detects fe80/fd00 and appends the right
        # platform-specific index (Linux ifname / Windows v6 ifIndex);
        # for v4 and v6 globals it returns the address unchanged.
        dest_ip = str(self.dest_info["ip"])
        if self.af == IP6:
            nic_id = self.nic.get_nic_id(IP6) if self.nic is not None else None
            dest_ip = patch_connect_ip(self.af, dest_ip, nic_id)
        dest = (dest_ip, self.dest_info["port"])
        log(fstr(
            "direct_connect[{0}]: af={1} dest={2} nic.id={3} reply={4}",
            (self.plugin_id, self.af, dest, getattr(self.nic, "id", "?"), reply is not None),
        ))
        print("[DIRECT-DBG] plugin_id={0} af={1} dest_ip={2} dest_port={3} src_loopback={4} nic_id={5}".format(
            self.plugin_id, self.af, dest[0], dest[1],
            self.src_info.get("loopback") if self.src_info else None,
            getattr(self.nic, "id", "?"),
        ))

        if is_loopback_dest_str(dest[0], self.af):
            # Same-machine loopback path. Walk every candidate in order
            # so we cover both the per-pubkey alias and the universal
            # 127.0.0.1 / ::1 fallbacks (and the pubkey-port collision
            # backstop). First successful connect wins; the plugin
            # registers that pipe and returns.
            candidates = loopback_dest_candidates(self, dest)
            print("[DIRECT-DBG] {0} loopback candidates: {1}".format(self.plugin_id, candidates))
            pipe = await self.try_loopback_candidates(candidates)
            if pipe is None:
                return
        else:
            # Non-loopback path: standard NIC-bind connect.
            print("[DIRECT-DBG] non-loopback dest, default route bind for dest={0}".format(dest))
            if self.af == IP4:
                route = await self.nic.route(self.af).bind()
            if self.af == IP6:
                if "fe80" == dest[0][:4]:
                    route = self.nic.route(self.af)
                    await route.bind(ips=str(route.link_locals[0]))
                else:
                    route = await self.nic.route(self.af).bind()
            log(fstr(
                "direct_connect[{0}]: bound, attempting TCP connect to {1}",
                (self.plugin_id, dest),
            ))
            try:
                # Fail-fast on dead paths so a single combo doesn't dominate
                # the auto_connect batch budget. 2.5s covers slow-LAN /
                # WAN-via-router; longer than that on a real direct path is
                # almost always a hairpinning/dead-route timeout that would
                # have failed at the kernel timeout in any case.
                pipe = await asyncio.wait_for(
                    Pipe(TCP, dest, route).connect(),
                    timeout=2.5,
                )
            except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
                print("[DIRECT-DBG] TCP connect to {0} raised: {1!r}".format(dest, exc))
                log_exception()
                pipe = None
            if pipe is None:
                print("[DIRECT-DBG] TCP connect to {0} returned None".format(dest))
                log(fstr(
                    "direct_connect[{0}]: TCP connect to {1} returned None",
                    (self.plugin_id, dest),
                ))
                return
            print("[DIRECT-DBG] TCP connect to {0} OK, pipe={1!r}".format(dest, pipe))

        if pipe.sock is None:
            log(fstr(
                "direct_connect[{0}]: pipe.sock is None after connect",
                (self.plugin_id,),
            ))
            return

        # In-band ConId frame: write b"P2P-CID:<plugin_id>\n" as the
        # very first bytes on the new TCP pipe. Same channel as the
        # data pipe means no cross-channel race with a separate signal
        # round-trip -- the responder's node_protocol peels off this
        # frame on the first inbound message and resolves the
        # reverse_connect inbound future for plugin_id directly.
        con_id_frame = CON_ID_PREFIX + to_b(self.plugin_id) + b"\n"
        print("[CON-ID-DBG] {0} sending in-band ConId frame ({1} bytes) on pipe...".format(
            self.plugin_id, len(con_id_frame),
        ))
        try:
            await pipe.send(con_id_frame)
            print("[CON-ID-DBG] {0} in-band ConId send returned cleanly".format(
                self.plugin_id,
            ))
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            print("[CON-ID-DBG] {0} in-band ConId send raised: {1!r}".format(
                self.plugin_id, exc,
            ))
            log_exception()
        log(fstr(
            "direct_connect[{0}]: in-band ConId frame sent, setting result",
            (self.plugin_id,),
        ))
        self.result.set_result(pipe)
        print("[CON-ID-DBG] {0} plugin.result.done()={1}".format(
            self.plugin_id, self.result.done(),
        ))

    async def try_loopback_candidates(self, candidates: List[Tuple[str, int]]) -> Optional[Any]:
        """Walk the loopback (ip, port) candidate list, returning the first
        connected Pipe. Returns None if every candidate failed.

        Each candidate is given a fresh route bound on alice's loopback
        source (her own per-node alias when present, else a literal
        127.0.0.1 / ::1). A short per-candidate timeout keeps the
        outer auto_connect timeout budget honest -- without it a single
        slow candidate could starve the rest.
        """
        per_cand_timeout = 4.0
        for ip, port in candidates:
            target = (ip, port)
            try:
                # Match the connect-socket source to the destination's
                # loopback class. On Windows XP only 127.0.0.1 is
                # routable, so binding src to alice's per-pubkey
                # 127.X.Y.Z (even when dest is 127.0.0.1) makes the
                # whole connect time out. Picking src by dest category
                # keeps the path symmetric and works across XP, Vista,
                # 7, 8.1, 10, 11, Linux, macOS.
                if self.af == IP4:
                    if ip == "127.0.0.1":
                        src_str = "127.0.0.1"
                    else:
                        src_lo = loopback_src_for(self)
                        src_str = src_lo if (src_lo and src_lo.startswith("127.")) else "127.0.0.1"
                else:
                    src_str = "::1"
                # Loopback destinations don't traverse any physical NIC,
                # so binding the connect socket to self.nic (e.g. ens37
                # via SO_BINDTODEVICE) makes the Linux kernel reject
                # the connect to 127.x with EINVAL: 127.x isn't reachable
                # through ens37, only through lo.  Build the loopback
                # connect on the default Interface for THIS attempt only;
                # the per-NIC route stays the source of truth for every
                # other path direct_connect drives.
                default_nic = await Interface("default")
                route = default_nic.route(self.af)
                await route.bind(ips=src_str)
                print("[DIRECT-DBG] {0} loopback try src={1} dest={2}".format(
                    self.plugin_id, src_str, target,
                ))
                pipe = await asyncio.wait_for(
                    Pipe(TCP, target, route).connect(),
                    timeout=per_cand_timeout,
                )
            except asyncio.CancelledError:  # pylint: disable=try-except-raise
                raise
            except (OSError, ConnectionError, asyncio.TimeoutError, ValueError) as exc:
                print("[DIRECT-DBG] {0} loopback dest={1} failed: {2!r}".format(
                    self.plugin_id, target, exc,
                ))
                continue
            if pipe is None:
                print("[DIRECT-DBG] {0} loopback dest={1} returned None".format(
                    self.plugin_id, target,
                ))
                continue
            print("[DIRECT-DBG] {0} loopback dest={1} OK, pipe={2!r}".format(
                self.plugin_id, target, pipe,
            ))
            return pipe
        print("[DIRECT-DBG] {0} all loopback candidates failed".format(self.plugin_id))
        return None


PLUGIN_CLASS = DirectConnect

# direct_connect no longer owns any signal-channel messages.
# The connection-request side stays at the core layer (ConMsg, registered
# centrally by build_core_sig_proto). The follow-up rendezvous that used
# to be a signal-channel ConIdMsg now travels in-band as the very first
# bytes on the new TCP pipe (see con_id_frame.CON_ID_PREFIX). One channel,
# no cross-channel race.
