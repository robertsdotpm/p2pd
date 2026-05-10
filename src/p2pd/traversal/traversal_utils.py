"""Utility functions shared across traversal strategies."""
import asyncio
from aionetiface import (
    IP4, IP6, IPRange, af_bitlen,
    NIC_BIND, EXT_BIND, LOOPBACK_BIND,
    to_s, to_b, to_h, h_to_b, rand_plain,
    fstr, log, log_p2p, log_exception,
    async_wrap_errors, decrypt, encrypt,
    cancel_task, cancel_tasks,
)
from ..protocol.proto_msg import ProtoMsg

__all__ = ["cancel_task", "cancel_tasks"]


def f_path_txt(x):
    """Return 'local' for NIC_BIND paths, 'external' otherwise."""
    return "local" if x == NIC_BIND else "external"


# Routing-decision keys that resolve_pair strips off the per-side dicts
# before plugins see them.  After resolution the only addressing fields
# that remain are "ip" + "port" -- the resolved local-bind / peer-dial
# pair for the chosen route_type.  Peer metadata (if_index, nat,
# netiface_index, machine_id, pub_key_hex, …) stays.
RESOLVE_DROP_KEYS = (
    "nic", "ext", "loopback",
    "nic_port", "ext_port",
    "loopback_candidates",
)


def _select_local_bind(af, route_type, src, dest):
    """Pick the local (ip, port) pair to bind for this route_type."""
    if route_type == LOOPBACK_BIND:
        ip = src.get("loopback")
        port = src.get("nic_port", src.get("port"))
    elif route_type == NIC_BIND:
        ip = src["nic"]
        port = src.get("nic_port", src.get("port"))
    elif route_type == EXT_BIND:
        # v4: NAT box rewrites src; kernel binds to the local LAN
        # address (src["nic"]) and the peer sees src["ext"].
        # v6: no NAT in the path -- bind == advertise == ext (global).
        # make_node_addr serialises v6's nic as fe80 link-local when
        # any link-local exists on the route (topology.py:428-430),
        # so binding to src["nic"] for v6 EXT_BIND would put us on a
        # link-local source addr that can't reach a global remote.
        if af == IP6:
            ip = src.get("ext") or src["nic"]
        else:
            ip = src["nic"]
        port = src.get("ext_port", src.get("port"))
    else:
        raise ValueError(fstr("resolve_pair: unknown route_type {0}", (route_type,)))
    return ip, port


def _select_remote_dial(af, route_type, src, dest):
    """Pick the (ip, port) pair to dial on the peer for this route_type."""
    if route_type == LOOPBACK_BIND:
        ip = dest.get("loopback")
        port = dest.get("nic_port", dest.get("port"))
    elif route_type == NIC_BIND:
        # v6 mirror of the local-bind logic: dest["nic"] is the peer's
        # fe80 link-local when any v6 link-local exists on their route.
        # That's only reachable on a shared L2 segment; for cross-link
        # we want their global v6 -- which lives in dest["ext"].
        if af == IP6:
            dest_nic = dest.get("nic")
            if dest_nic is None or str(dest_nic).lower().startswith("fe80"):
                ip = dest.get("ext") or dest_nic
            else:
                ip = dest_nic
        else:
            ip = dest["nic"]
        port = dest.get("nic_port", dest.get("port"))
    elif route_type == EXT_BIND:
        ip = dest["ext"]
        port = dest.get("ext_port", dest.get("port"))
    else:
        raise ValueError(fstr("resolve_pair: unknown route_type {0}", (route_type,)))
    return ip, port


def resolve_pair(af, route_type, src, dest, nic, same_machine=False):
    """Resolve a (src, dest) pair into the bind / dial values
    a plugin will actually use.

    Returns ``(src_resolved, dest_resolved)`` -- shallow copies of the
    inputs with two changes:

      1.  ``ip`` / ``port`` set to the chosen local bind / peer dial
          values for *route_type*.  v6 link-local destinations get the
          paired link-local source plus ``%scope`` patched into both
          sides so Windows connect_ex works.
      2.  Routing-decision keys (nic / ext / loopback / nic_port /
          ext_port / loopback_candidates) are removed.  Plugins that
          need additional info beyond (ip, port) read it from the
          local NIC object directly, not from the per-side dict.

    Peer metadata (if_index, nat, netiface_index, machine_id,
    pub_key_hex, …) is preserved -- plugins legitimately need NAT
    shape, if_index, etc.
    """
    src_ip, src_port = _select_local_bind(af, route_type, src, dest)
    dest_ip, dest_port = _select_remote_dial(af, route_type, src, dest)

    # v6 link-local fix-up: paired source must also be link-local, and
    # both sides need %scope_id appended for the Windows TCP stack to
    # route the SYN out the right interface.  Linux's getaddrinfo
    # tolerates a bare fe80::, but baking the scope is harmless there
    # and removes the cross-platform branch from every plugin.
    if af == IP6 and dest_ip is not None and str(dest_ip).lower().startswith("fe80"):
        if nic is not None:
            try:
                local_link = nic.route(af).link_locals[0]
                src_ip = str(local_link)
            except (IndexError, AttributeError, ValueError):
                pass
            try:
                from aionetiface.net.bind.bind_utils import ip6_patch_bind_ip
                scope = nic.get_nic_id(af)
                if scope is not None:
                    dest_ip = ip6_patch_bind_ip(str(dest_ip).split("%", 1)[0], scope)
                    src_ip = ip6_patch_bind_ip(str(src_ip).split("%", 1)[0], scope)
            except (ImportError, AttributeError, ValueError):
                pass

    # Strict mode: per-side dict carries only the resolved (ip, port)
    # plus peer metadata (if_index, nat, netiface_index, machine_id,
    # pub_key_hex, bytes, ...).  Raw routing-decision keys (nic / ext
    # / loopback / nic_port / ext_port / loopback_candidates) are
    # filtered out so plugins can't accidentally do per-route-type
    # selection inside their run().
    def strip(info):
        return {k: v for k, v in info.items() if k not in RESOLVE_DROP_KEYS}
    src_resolved = strip(src)
    src_resolved["ip"] = str(src_ip) if src_ip is not None else None
    src_resolved["port"] = src_port
    dest_resolved = strip(dest)
    dest_resolved["ip"] = str(dest_ip) if dest_ip is not None else None
    dest_resolved["port"] = dest_port
    _ = same_machine  # accepted for future fixups (multi-NIC same-pc edge case)
    return src_resolved, dest_resolved


def select_dest_ipr(af, same_pc, src, dest, addr_types, has_set_bind=True):
    """Select the best destination IPRange for a traversal attempt.

    Nodes behind the same router share an external address; in that case the
    private NIC address is used instead so the connection does not loop back
    through the router.
    """
    # Shorten these for expressions.
    src_nid = src["netiface_index"]
    dest_nid = dest["netiface_index"]

    # Same-LAN detection. The right question for the NIC_BIND path is
    # "is dest reachable via my directly-connected interface, with no
    # router hop?" -- i.e. is dest's IP within MY nic's directly-
    # connected subnet. When the wire format ships our peer's NIC
    # subnet (9-field addr), use it; otherwise fall back to the v4
    # ext-equality heuristic.
    same_lan = False
    src_nic_subnet = getattr(src["nic"], "subnet", None)
    if src_nic_subnet is not None and src_nic_subnet > 0:
        host_bits = af_bitlen(af) - src_nic_subnet
        if af == IP6 and str(src["nic"]).lower().startswith("fe80:"):
            try:
                src_net = IPRange(str(src["ext"]), bitlen=host_bits)
                same_lan = dest["ext"] in src_net
            except (ValueError, TypeError):
                same_lan = False
        else:
            try:
                src_net = IPRange(str(src["nic"]), bitlen=host_bits)
                same_lan = (
                    dest["nic"] in src_net or dest["ext"] in src_net
                )
            except (ValueError, TypeError):
                same_lan = False
    else:
        same_lan = src["ext"] == dest["ext"]

    # Makes long conditions slightly more readable.
    same_if = src_nid == dest_nid
    same_if_on_host = same_pc and same_if

    # There may be multiple compatible addresses per info.
    # Caller controls priority via the order of addr_types.
    for addr_type in addr_types:
        # Per-node 127.X.Y.Z (or ::1) loopback alias. Only meaningful
        # for same-machine peers and only when both sides have a
        # loopback IP attached (set by enrich_addr_map_with_loopback).
        if addr_type == LOOPBACK_BIND:
            if not same_pc:
                continue
            lo = dest.get("loopback")
            if lo is None:
                continue
            return lo

        # Public WAN address. Skip when both nodes share the same
        # external address (same NAT / same machine with the same
        # global IP) -- the connection would loop back through the
        # router or fail. When ext IPs differ (different ISPs etc.)
        # it's the natural cross-machine path.
        if addr_type == EXT_BIND:
            if src["ext"] == dest["ext"]:
                continue
            return dest["ext"]

        # Local NIC address.
        #
        # v6 global NIC addresses are publicly routable (no NAT for v6),
        # so they are valid for any pairing -- skip the same_lan gate.
        #
        # v6 link-local (fe80::/10) addresses are only valid on the same
        # L2 segment; skip them when the peers are not on the same LAN.
        #
        # v4 private NIC addresses are only reachable within the same LAN
        # (same NAT router = same external IP); skip otherwise.
        if addr_type == NIC_BIND:
            if not has_set_bind:
                pass
            if af == IP6:
                nic_str = str(dest["nic"]).lower().split("%")[0]
                if not nic_str.startswith("fe80:"):
                    return dest["nic"]
            if not (same_pc or same_lan):
                continue
            return dest["nic"]

    # No compatible addresses.
    return None


def sort_pairs_by_overlap(srcs, dests):
    """Partition (src, dest) pairs into overlapping and non-overlapping external IPs."""
    overlap = []
    unique = []
    for src in srcs:
        for dest in dests:
            pair = [src, dest]
            if src["ext"] == dest["ext"]:
                overlap.append(pair)
            else:
                unique.append(pair)

    return overlap, unique


async def for_addr_infos(
strat,
    func,
    timeout,
    cleanup,
    has_set_bind,
    max_pairs,
    reply,
    pp,
    conf,
):
    """
    Given info on a local interface, a remote interface,
    and a chosen connectivity technique, attempt to create
    a connection. Adapt the technique depending on whether
    addressing is suitably local or remote.
    """

    async def try_addr_infos(af, strat, addr_type, src, dest):
        """Attempt one connectivity strategy for a specific src/dest interface pair."""
        # Local addressing and/or remote.
        try:
            # Create a future for pending pipes.
            if reply is None:
                pipe_id = to_s(rand_plain(15))
            else:
                pipe_id = reply.meta.pipe_id

            # Allow awaiting by pipe_id.
            pp.node.pipe_future(pipe_id)

            # Select interface to use.
            if_index = src["if_index"]
            interface = pp.node.ifs[if_index]

            # Ensure our selected NIC is what the
            # remote peer wanted to use for the technique.
            if reply is not None:
                if reply.routing.dest_index != if_index:
                    return

            # Determine the best destination IP to use
            # for the connectivity technique based on
            # addressing and relationships between the
            # two machines (deep networking specific.)
            dest_ip = select_dest_ipr(
                af,
                pp.same_machine,
                src,
                dest,
                [addr_type],
                has_set_bind,
            )

            # Need a destination address.
            # Possibly a different address type will work.
            if dest_ip is None:
                return

            dest["ip"] = str(dest_ip)

            # Use per-bind port when advertised (10-field wire format). Fall back to
            # the section's single port for peers on the old 8/9-field format.
            if addr_type == NIC_BIND:
                dest["port"] = dest.get("nic_port", dest["port"])
            elif addr_type == EXT_BIND:
                dest["port"] = dest.get("ext_port", dest["port"])

            # Detailed logging details.
            path_txt = f_path_txt(addr_type)
            src_ip = src["nic"] if addr_type == NIC_BIND else src["ext"]
            msg = fstr(
                "<{0}> Trying {1} {2} -> ",
                (
                    strat,
                    path_txt,
                    src_ip,
                ),
            )
            msg += fstr(
                "{0} on '{1}'",
                (
                    dest["ip"],
                    interface.name,
                ),
            )
            log_p2p(msg, pp.node.node_id[:8])

            # With all the correct interfaces and IPs
            # chosen -- call the function that will run
            # the technique to achieve connectivity.
            result = await async_wrap_errors(
                func(
                    pp,
                    af,
                    pipe_id,
                    src,
                    dest,
                    interface,
                    addr_type,
                    pp.same_machine,
                    reply,
                ),
                timeout,
            )

            if isinstance(result, ProtoMsg):
                msg = result
                msg.meta = ProtoMsg.Meta.from_dict(
                    {
                        "ttl": int(pp.node.sys_clock.time()) + 30,
                        "pipe_id": pipe_id,
                        "af": af,
                        "src_buf": pp.src_bytes,
                        "src_index": src["if_index"],
                        "addr_types": [addr_type],
                    }
                )

                msg.routing = ProtoMsg.Routing.from_dict(
                    {
                        "af": af,
                        "dest_buf": pp.dest_bytes,
                        "dest_index": dest["if_index"],
                    }
                )

                vk = to_h(pp.node.vk.to_string("compressed"))
                pp.node.sig_msg_queue.put_nowait([msg, vk, 0])

            # Success result from function.
            if result is not None:
                return result

            # Some functions require cleanup on failure.
            # Ensure that the state overtime remains clean.
            if cleanup is not None:
                await cleanup(
                    af,
                    pipe_id,
                    src,
                    dest,
                    interface,
                    addr_type,
                    reply,
                )

            # Delete unused futures on failure.
            if pipe_id in pp.node.inbound_pipes:
                del pp.node.inbound_pipes[pipe_id]
        except (OSError, ConnectionError, asyncio.TimeoutError):
            log_exception()

    # Use an AF supported by both.
    if reply is not None:
        conf["addr_families"] = [reply.meta.af]

    for addr_type in conf["addr_types"]:
        count = 1
        for af in conf["addr_families"]:
            if reply is not None:
                # Try select if info based on their chosen offset.
                src = pp.src[af][reply.routing.dest_index]
                dest = pp.dest[af][reply.meta.src_index]
                ret = await async_wrap_errors(
                    try_addr_infos(af, strat, addr_type, src, dest)
                )

                return ret, addr_type

            # Get interface offset that supports this af.
            # for src, dest in if_info_iter:
            srcs = list(pp.src[af].values())
            dests = list(pp.dest[af].values())
            overlap, unique = sort_pairs_by_overlap(srcs, dests)

            # If external address is the same try unique pairs first.
            if addr_type == EXT_BIND:
                pair_order = unique + overlap

            # For local addresses you want to do the opposite.
            # So you're on the same LAN or NIC if on the same machine.
            if addr_type == NIC_BIND:
                pair_order = overlap + unique

            if not pair_order:
                log("pair order list is empty!")

            for src, dest in pair_order:
                # Only try up to N pairs per technique.
                # Technique-specific N to avoid lengthy delays.
                ret = await async_wrap_errors(
                    try_addr_infos(af, strat, addr_type, src, dest)
                )

                # Success so return.
                if ret is not None:
                    return ret, addr_type

                count += 1
                if count > max_pairs:
                    return None, None

                # Cleanup here?

    # Failure.
    return None, None


# TODO: make this work with everything.


def get_if_infos_order(af, route_type, src_map, dest_map):
    """
    Given a list of interface details
    for an address family indexed by interface
    offset return a list of them directly.
    """
    srcs = list(src_map[af].values())
    dests = list(dest_map[af].values())

    # Given two lists of interface details, break them into
    # two lists of (src, dest) pairs. The first
    # contains pairs for which both interface details have the
    # same ext (external address). The other is non-overlapping,
    # where both have different addresses.
    overlap, unique = sort_pairs_by_overlap(srcs, dests)

    # If the route type is external then using the same external
    # address for overlapping pairs is likely not to lead to
    # a connection since both are behind the same router.
    if route_type in (EXT_BIND, None):
        pair_order = unique + overlap

    # For local addresses you want to do the opposite.
    # So you're on the same LAN or NIC if on the same machine.
    if route_type == NIC_BIND:
        pair_order = overlap + unique

    # LOOPBACK_BIND is a same-machine path (both sides have a
    # loopback alias attached). Same priority as NIC_BIND --
    # overlap first since same-machine pairs typically share the
    # ext too.
    if route_type == LOOPBACK_BIND:
        pair_order = overlap + unique

    return pair_order


def try_unpack_msg(buf, sk, sig_proto_map):
    """Decrypt (if needed) and deserialise an incoming signal buffer into a protocol message.

    Wire layout (after stripping the encryption framing):

        [name_len: 1 byte][wire_name: ASCII][JSON payload]

    The wire_name is looked up against sig_proto_map (keys are the
    same strings plugins register via PROTO_MESSAGES) to find the
    receiver-side msg_class. Replaces the old single-byte enum so
    plugins never have to coordinate enum allocation.
    """
    buf = h_to_b(buf)

    # Try to decrypt message if its encrypted.
    is_enc = buf[0]
    if is_enc:
        # Ensure a SK is set for decryption.
        if not sk:
            raise ValueError("No sk set for decryption.")

        # Will raise if it can't decrypt.
        buf = decrypt(sk, buf[1:])
        log(fstr("Recv decrypted {0}", (buf,)))

    # Otherwise buffer is not encrypted -- use as is.
    if not is_enc:
        buf = buf[1:]

    # Read length-prefixed wire_name + look up the class.
    if len(buf) < 1:
        raise ValueError("try_unpack_msg: empty payload")
    name_len = buf[0]
    if len(buf) < 1 + name_len:
        raise ValueError(
            "try_unpack_msg: truncated wire_name (len={0}, buf={1})".format(
                name_len, len(buf),
            )
        )
    wire_name = bytes(buf[1:1 + name_len]).decode("ascii", errors="replace")
    msg_info = sig_proto_map.get(wire_name)
    if msg_info is None:
        raise ValueError(
            "try_unpack_msg: unknown wire_name {0!r}".format(wire_name)
        )
    msg_class = msg_info[0]
    msg = msg_class.unpack(buf[1 + name_len:])
    return msg


def sig_msg_to_buf(msg, dest_pk):
    """Serialise a signal message, optionally encrypting it with the destination's public key."""
    if dest_pk:
        buf = b"\1" + encrypt(dest_pk, msg.pack())
    else:
        buf = b"\0" + msg.pack()

    # UTF-8 messes up binary data in MQTT.
    buf = to_h(buf)
    return to_b(buf)


async def close_plugin(plugin, plugins, inbound_pipes):
    """Release plugin resources and remove it from registries.

    Safe to call multiple times (pop is a no-op when the key is absent).
    Registry pop is intentionally deferred until here (not at result.done()
    time) to avoid the race where a follow-up PunchMsg signal arrives
    between the done() check and the pop and finds an empty registry slot,
    spawning a duplicate engine that collides on the same predicted ports.
    By the time close_plugin is called the result is already resolved so no
    further signals for this plugin_id are in-flight.
    """
    plugin_id = getattr(plugin, "plugin_id", None)
    plugins.pop(plugin_id, None)

    fut = inbound_pipes.pop(plugin_id, None)
    if fut is not None and not fut.done():
        fut.cancel()

    if not plugin.result.done():
        plugin.result.cancel()

    close_fn = getattr(plugin, "close", None)
    if close_fn is not None:
        try:
            await asyncio.wait_for(close_fn(), timeout=5.0)
        except (asyncio.TimeoutError, OSError):
            log_exception()
        except asyncio.CancelledError:
            pass
