"""Utility functions shared across traversal strategies."""
from typing import Any, Dict, List, Optional, Tuple
import asyncio
from aionetiface import (
    IP4, IP6,
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


def select_dest_ipr(af: Any, same_pc: bool, src_info: Dict[str, Any], dest_info: Dict[str, Any], addr_types: List[Any], has_set_bind: bool = True) -> Optional[Any]:
    """Select the best destination IPRange for a traversal attempt.

    Nodes behind the same router share an external address; in that case the
    private NIC address is used instead so the connection does not loop back
    through the router.
    """
    # Shorten these for expressions.
    src_nid = src_info["netiface_index"]
    dest_nid = dest_info["netiface_index"]

    # Very simplified -- another external address could
    # be routable for the same LAN. There must
    # be a better way to do this.
    if af == IP4:
        # Compares external v4 default route.
        same_lan = src_info["ext"] == dest_info["ext"]
    if af == IP6:
        # Compares the first n bits for typical v6 subnet.
        # Todo: need to know the subnet bits for this.
        same_lan = src_info["ext"] == dest_info["ext"]
        same_lan = 1

    # Try any local address for now.
    # Todo: write a better algorithm for this.
    same_lan = 1

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
            lo = dest_info.get("loopback")
            if lo is None:
                continue
            return lo

        # Public WAN address. Skip when both nodes share the same
        # external address (same NAT / same machine with the same
        # global IP) -- the connection would loop back through the
        # router or fail. When ext IPs differ (different ISPs etc.)
        # it's the natural cross-machine path.
        if addr_type == EXT_BIND:
            if src_info["ext"] == dest_info["ext"]:
                continue
            return dest_info["ext"]

        # Local NIC address. Different NICs on the same machine but
        # different L3 subnets won't generally interact (kernel
        # doesn't auto-loopback cross-subnet on Windows; LOOPBACK_BIND
        # covers that case). Same-NIC same-port works via the kernel's
        # local-route shortcut on every supported OS.
        if addr_type == NIC_BIND:
            if not has_set_bind:
                pass
            if not (same_pc or same_lan):
                continue
            return dest_info["nic"]

    # No compatible addresses.
    return None


def sort_pairs_by_overlap(src_infos: List[Dict[str, Any]], dest_infos: List[Dict[str, Any]]) -> Tuple[List[Any], List[Any]]:
    """Partition (src_info, dest_info) pairs into overlapping and non-overlapping external IPs."""
    overlap = []
    unique = []
    for src_info in src_infos:
        for dest_info in dest_infos:
            pair = [src_info, dest_info]
            if src_info["ext"] == dest_info["ext"]:
                overlap.append(pair)
            else:
                unique.append(pair)

    return overlap, unique


async def for_addr_infos(
strat: str,
    func: Any,
    timeout: int,
    cleanup: Optional[Any],
    has_set_bind: bool,
    max_pairs: int,
    reply: Optional[Any],
    pp: Any,
    conf: Dict[str, Any],
) -> Tuple[Optional[Any], Optional[Any]]:
    """
    Given info on a local interface, a remote interface,
    and a chosen connectivity technique, attempt to create
    a connection. Adapt the technique depending on whether
    addressing is suitably local or remote.
    """

    async def try_addr_infos(af: Any, strat: str, addr_type: Any, src_info: Dict[str, Any], dest_info: Dict[str, Any]) -> Optional[Any]:
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
            if_index = src_info["if_index"]
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
                src_info,
                dest_info,
                [addr_type],
                has_set_bind,
            )

            # Need a destination address.
            # Possibly a different address type will work.
            if dest_ip is None:
                return

            dest_info["ip"] = str(dest_ip)

            # Detailed logging details.
            path_txt = f_path_txt(addr_type)
            src_ip = src_info["nic"] if addr_type == NIC_BIND else src_info["ext"]
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
                    dest_info["ip"],
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
                    src_info,
                    dest_info,
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
                        "src_index": src_info["if_index"],
                        "addr_types": [addr_type],
                    }
                )

                msg.routing = ProtoMsg.Routing.from_dict(
                    {
                        "af": af,
                        "dest_buf": pp.dest_bytes,
                        "dest_index": dest_info["if_index"],
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
                    src_info,
                    dest_info,
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
                src_info = pp.src[af][reply.routing.dest_index]
                dest_info = pp.dest[af][reply.meta.src_index]
                ret = await async_wrap_errors(
                    try_addr_infos(af, strat, addr_type, src_info, dest_info)
                )

                return ret, addr_type

            # Get interface offset that supports this af.
            # for src_info, dest_info in if_info_iter:
            src_infos = list(pp.src[af].values())
            dest_infos = list(pp.dest[af].values())
            overlap, unique = sort_pairs_by_overlap(src_infos, dest_infos)

            # If external address is the same try unique pairs first.
            if addr_type == EXT_BIND:
                pair_order = unique + overlap

            # For local addresses you want to do the opposite.
            # So you're on the same LAN or NIC if on the same machine.
            if addr_type == NIC_BIND:
                pair_order = overlap + unique

            if not pair_order:
                log("pair order list is empty!")

            for src_info, dest_info in pair_order:
                # Only try up to N pairs per technique.
                # Technique-specific N to avoid lengthy delays.
                ret = await async_wrap_errors(
                    try_addr_infos(af, strat, addr_type, src_info, dest_info)
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


def get_if_infos_order(af: Any, route_type: Any, src_map: Dict[Any, Any], dest_map: Dict[Any, Any]) -> List[Any]:
    """
    Given a list of interface details
    for an address family indexed by interface
    offset return a list of them directly.
    """
    src_infos = list(src_map[af].values())
    dest_infos = list(dest_map[af].values())

    # Given two lists of interface details, break them into
    # two lists of (src_info, dest_info) pairs. The first
    # contains pairs for which both interface details have the
    # same ext (external address). The other is non-overlapping,
    # where both have different addresses.
    overlap, unique = sort_pairs_by_overlap(src_infos, dest_infos)

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


def try_unpack_msg(buf: Any, sk: Any, sig_proto_map: Dict[Any, Any]) -> Any:
    """Decrypt (if needed) and deserialise an incoming signal buffer into a protocol message."""
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

    # Unpack message into fields.
    msg_info = sig_proto_map[buf[0]]
    msg_class = msg_info[0]
    msg = msg_class.unpack(buf[1:])
    return msg


def sig_msg_to_buf(msg: Any, dest_pk: Optional[Any]) -> bytes:
    """Serialise a signal message, optionally encrypting it with the destination's public key."""
    if dest_pk:
        buf = b"\1" + encrypt(dest_pk, msg.pack())
    else:
        buf = b"\0" + msg.pack()

    # UTF-8 messes up binary data in MQTT.
    buf = to_h(buf)
    return to_b(buf)


async def close_plugin(plugin: Any, plugins: Dict[str, Any], inbound_pipes: Dict[str, Any]) -> None:
    """Remove a plugin from the registries and call its close method if present."""
    if hasattr(plugin, "plugin_id"):
        plugins.pop(plugin.plugin_id, None)
        inbound_pipes.pop(plugin.plugin_id, None)

    close_fn = getattr(plugin, "close", None)
    if callable(close_fn):
        try:
            result = close_fn()
            if asyncio.iscoroutine(result):
                await result
        except (OSError, asyncio.TimeoutError):
            log_exception()
