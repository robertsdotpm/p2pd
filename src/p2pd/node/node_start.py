"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""

from typing import Any, Callable, Optional
import asyncio
import hashlib
import time
from aionetiface import (
    fstr, log, log_exception, log_p2p, async_wrap_errors,
    IP4, IP6, OPEN_INTERNET, AFGroup, Interface, SysClock,
    list_interfaces, load_interfaces, parse_node_addr, make_node_addr,
    field_wrap, dhash, create_task, Signing,
)
from sidewire import Router
from .node_utils import (
    load_machine_id,
    resolve_install_path,
    load_signing_key,
    load_stun_clients,
    close_idle_pipes,
    listen_on_ifs,
    forward,
    remote_reachability_cb,
    enrich_addr_map_with_loopback,
)
from .nickname import Nickname
from ..traversal.traversal_manager import TraversalManager
from ..traversal.plugin_loader import load_plugins
from ..install_check import verify_sibling_installs


# ==========================================
# Orchestrates the startup sequence for a P2P node.
# ==========================================
async def node_start(node: Any, sys_clock: Optional[Any] = None, out: bool = False, cout: Callable = print) -> Any:
    """Execute the full ordered startup sequence for a P2P node and return it when ready.

    WARNING -- propagation race after node_start returns
    ====================================================

    On return, the node has put its PNP record on the configured PNP
    servers and subscribed to its MQTT signaling topic. Those operations
    may not yet be visible to every server in the pool. A peer that
    resolves this node's nickname, or routes signaling via its MQTT
    topic, in the immediate window after node_start returns can race a
    server that hasn't yet seen the put / accepted the subscribe, and
    will silently hang in the resolve or dispatch step.

    This affects EVERY caller whose flow is listener-then-connector --
    which is every cross-node test in the matrix. The connector side
    MUST allow a settling window before it starts resolving the
    listener's nickname; ~8 seconds is sufficient in practice. The
    demo entry point enforces this with `await asyncio.sleep(8)` after
    Nickname.put completes (see demo/__main__.py:setup_node). Tests
    or callers that bypass setup_node must insert an equivalent sleep
    themselves before any cross-node lookup.
    """
    # Print where each sibling repo's package resolved from. Cheap
    # (4 imports, ms-scale) and gives every node log a header that
    # makes stale-install bugs (e.g. aionetiface imported from a
    # checkout outside ~/projects/) instantly diagnosable. Non-strict
    # so library / PyPI users aren't forced into the dev layout.
    verify_sibling_installs(strict=False)

    # Hardware & Network Setup
    await load_network_interfaces(node)

    # Identity & Security
    await load_machine_identity(node)
    kp = load_cryptography_and_auth(node)

    # Time & Synchronization
    # Must complete BEFORE the Router (and its MQTTClient instances) is
    # constructed: each MQTTClient takes get_time at __init__ and uses
    # it to stamp app-packet timestamps. Patching get_time on the
    # Router post-hoc doesn't propagate to already-constructed
    # MQTTClients, which silently kept using time.time -- the silent
    # fallback that hid a multi-hour clock-skew bug between
    # XP/Vista (BIOS clock drift) and modern VMs (NTP-synced).
    await initialize_system_clock(node, sys_clock, out, cout)

    # STUN clients + Router can run concurrently now that sys_clock
    # is established and can be passed into Router at construction.
    await asyncio.gather(
        load_p2p_stun_clients(node, out, cout),
        setup_router_and_signal(node, kp, out, cout),
    )

    await initialize_punch_coordination(node, out, cout)

    # Start Servers
    start_maintenance_tasks(node)
    await listen_on_ifs(node)

    # Finalize Connectivity — start UPnP only after the node is listening and
    # the listen port is known; await it after high-level setup so UPnP runs
    # concurrently with nickname and plugin initialisation.
    build_node_address(node, out)
    upnp_task = start_background_port_forwarding(node)

    # High-Level Services
    await setup_nickname_service(node)
    await setup_traversal_plugins(node)

    await finalize_port_forwarding(node, upnp_task, out, cout)

    return node


# ==========================================
# Phase: Hardware & Network Setup
# ==========================================
async def load_network_interfaces(node: Any) -> None:
    """Discover and sort all available network interfaces, raising RuntimeError if none are found."""
    if not node.ifs:
        try:
            if_names = await list_interfaces()
            node.ifs = await load_interfaces(if_names, Interface)
        except asyncio.CancelledError:  # pylint: disable=try-except-raise
            raise
        except (OSError, asyncio.TimeoutError):
            log_exception()
            node.ifs = []

    # Ensure deterministic order
    node.ifs = sorted(node.ifs, key=lambda x: x.name)

    if not node.ifs:
        raise AssertionError("p2p node could not load ifs.")


def start_background_port_forwarding(node: Any) -> Optional[Any]:
    """Launch a background UPnP port-forwarding task if the node is behind NAT and UPnP is enabled."""
    # Check if all NICs are already open
    all_open_internet = True
    for nic in node.ifs:
        if nic.nat["type"] != OPEN_INTERNET:
            all_open_internet = False
            break

    # If UPnP is enabled and we are behind NAT, start the task
    if node.conf["enable_upnp"] and not all_open_internet:
        reachability = {IP4: {}, IP6: {}}

        async def reachability_cb(msg: Any, client_tup: Any, pipe: Any) -> None:
            """Forward inbound messages to the shared reachability checker."""
            await remote_reachability_cb(reachability, msg, client_tup, pipe)

        node.add_msg_cb(reachability_cb)

        return asyncio.create_task(
            async_wrap_errors(forward(node, node.listen_port, reachability))
        )
    return None


# ==========================================
# Phase: Identity & Security
# ==========================================
async def load_machine_identity(node: Any) -> None:
    """Load or derive a stable machine ID and set the node's listen port deterministically."""
    node.machine_id = await load_machine_id("p2pd", node.ifs[0].netifaces)

    if node.machine_id in (None, ""):
        raise AssertionError("Could not load machine id.")

    # The listen port is set deterministically to avoid conflicts
    # with port forwarding with multiple nodes in the LAN.
    if node.listen_port is None:
        node.listen_port = field_wrap(dhash(node.machine_id), [10000, 60000])


def load_cryptography_and_auth(node: Any) -> Any:
    """Load or generate the node's ECDSA signing key, derive the node ID, and return the keypair."""
    install_path = resolve_install_path(node.conf)
    node.sk = load_signing_key(
        node.ifs, node.listen_ips, node.listen_port, install_path,
        node_name=getattr(node, "node_name", None),
    )
    node.vk = node.sk.verifying_key

    node.node_id = hashlib.sha256(node.vk.to_string("compressed")).hexdigest()[:25]

    # Table of authenticated users
    node.auth = {
        node.node_id: {
            "sk": node.sk,
            "vk": node.vk.to_string("compressed"),
        }
    }

    node.kp = Signing(node.sk)
    return node.kp


# ==========================================
# Phase: Time & Synchronization (concurrent)
# ==========================================
async def initialize_system_clock(node: Any, sys_clock: Optional[Any], out: bool, cout: Callable) -> None:
    """Create or reuse the system clock, optionally synchronising it against NTP."""
    if sys_clock is None:
        if node.conf["init_clock_skew"]:
            sys_clock = SysClock(interface=node.ifs[0])
            await sys_clock.start()
        else:
            sys_clock = SysClock(node.ifs[0], ntp=time.time())
            node.sys_clock = sys_clock

    # Store reference if passed in or created
    if not hasattr(node, "sys_clock") or node.sys_clock is None:
        node.sys_clock = sys_clock


async def load_p2p_stun_clients(node: Any, out: bool, cout: Callable) -> None:
    """Load TCP STUN clients for each interface and AF if hole-punching is enabled."""
    if node.conf.get("enable_punching", True):
        if out:
            cout("\tLoading STUN clients...")
        # Returns TCP STUN clients using PUNCH_CONF.
        node.stun_clients = await load_stun_clients(node.ifs)

        if out:
            buf = ""
            for if_index in range(0, len(node.ifs)):
                nic = node.ifs[if_index]
                buf += "\t\t" + nic.name + " "
                for af in nic.supported():
                    af_txt = "V4" if af is IP4 else "V6"
                    buf += fstr(
                        "({0}={1})",
                        (
                            af_txt,
                            str(len(node.stun_clients[af][if_index])),
                        ),
                    )
            cout(buf)


async def setup_router_and_signal(node: Any, kp: Any, out: bool, cout: Callable) -> None:
    """Instantiate the MQTT router, install default traversal plugins, and start the signal channel."""
    # node.sys_clock is established by initialize_system_clock which
    # runs before this in node_start. Threading get_time at Router
    # construction means every MQTTClient stamps app-packet timestamps
    # off the same NTP-synced clock, instead of falling back to
    # wall-clock time.time (which on XP/Vista can be hours off).
    # Use Interface("default") for Router so MQTT brokers go via the
    # OS default route (the proven primary-NIC path that 8.8.8.8 probe
    # picks at startup). Building AFGroup.from_interfaces(node.ifs)
    # here was tempting -- it would let multi-homed hosts express
    # per-AF NIC preference automatically -- but on VMs with a
    # secondary mobile/CGNAT NIC, node.ifs[0] is sometimes the slow
    # one, which silently routed every broker connection through CGNAT
    # and broke convergence. Multi-homed callers who genuinely want a
    # per-AF split should construct an AFGroup explicitly and pass it
    # to Router; default stays "do what the OS does."
    router = Router(
        kp,
        nic=Interface("default"),
        get_time=node.sys_clock.time,
    )
    node.traversal = TraversalManager(
        router, node.stop_reader, node.inbound_pipes, node.ifs,
        # Pass node.msg_cb so any pipe created inside a plugin
        # (e.g. tcp_punch's reverse_server) can pre-populate
        # pipe_events.msg_cbs before the first inbound byte arrives.
        node_msg_cb=node.msg_cb,
    )
    router.add_msg_handler(node.traversal.recv_signal_msg)

    node.traversal.kp = node.kp

    await setup_signal_router(node, router, out, cout)


async def setup_signal_router(node: Any, router: Any, out: bool, cout: Callable) -> None:
    """Attach the router to the node and start MQTT subscriptions for inbound signalling."""
    node.router = router

    # Subscribe to our own MQTT topic so we can receive incoming signals.
    if out:
        cout("\tLoading MQTT router...")
    # XP's TCP/TLS-less MQTT handshake measurably slower than newer
    # Windows; observed ~8-12s on a fresh socket. 15s gives headroom
    # without dragging healthy hosts (which complete in <1s) into a
    # noticeably slower startup. router.start internally connects to
    # multiple MQTT brokers and racing the slower of them past 15s
    # is genuinely unhealthy.
    try:
        clients = await asyncio.wait_for(router.start(), timeout=15)
    except asyncio.TimeoutError as exc:
        raise OSError("Router MQTT start timed out - signaling may be degraded") from exc


# ==========================================
# Phase: Connectivity Clients
# ==========================================
async def initialize_punch_coordination(node: Any, out: bool, cout: Callable) -> None:
    """Log the NTP clock skew value used to coordinate hole-punch timing across peers."""
    if out:
        cout("\tLoading NTP clock skew...")
    if node.conf["init_clock_skew"]:
        ntp = str(node.sys_clock.ntp)
        if out:
            cout(fstr("\t\tClock ntp = {0}", (ntp,)))


# ==========================================
# Phase: Start Servers
# ==========================================
def start_maintenance_tasks(node: Any) -> None:
    """Launch the background idle-pipe-closer loop and register it for cancellation on shutdown."""
    # Simple loop to close idle tasks.
    node.resources.set_idle_closer(create_task(close_idle_pipes(node)))


# ==========================================
# Phase: Finalize Connectivity
# ==========================================
def build_node_address(node: Any, out: bool) -> None:
    """Serialise the node's public key and interface info into addr_bytes and parse it into addr_map."""
    if node.node_id is None:
        raise AssertionError("node_id was not set before building node address.")

    # Collect MQTT broker hints from router.protected_clients --
    # the brokers we successfully connected to at startup. Remote
    # peers resolving our addr will prefer publishing via these
    # before falling back to their own rendezvous-derived
    # candidate set, sidestepping the broker-set non-convergence
    # bug.
    #
    # MAX_BROKER_HINTS caps the count to keep the addr under
    # namebump's NB_VAL_LEN ceiling. Each hint is ~30-50 bytes
    # encoded; 3 hints with 4 base sections fits comfortably
    # under 500B. Two hints would give some redundancy but only
    # one mutually-reachable broker is needed for delivery, so
    # 3 is plenty in practice.
    MAX_BROKER_HINTS = 3
    mqtt_brokers = []
    try:
        for client in getattr(node.router, "protected_clients", set()) or []:
            af = getattr(client, "af", None)
            host, port = getattr(client, "dest", (None, None))
            if af is not None and host and port:
                mqtt_brokers.append({"af": int(af), "host": host, "port": int(port)})
            if len(mqtt_brokers) >= MAX_BROKER_HINTS:
                break
    except (AttributeError, TypeError):
        # If the router didn't finish setting up protected_clients
        # we just emit no hints; legacy 4-part addr behaviour.
        mqtt_brokers = []

    log_p2p(fstr(
        "[NODE-ADDR] packing {0}/{1} broker hints: {2}",
        (len(mqtt_brokers), MAX_BROKER_HINTS, mqtt_brokers),
    ), node.node_id[:8])

    node.addr_bytes = make_node_addr(
        node.kp.public_key_hex,
        node.machine_id,
        node.ifs,
        port=node.listen_port,
        mqtt_brokers=mqtt_brokers,
        if_ports=getattr(node, "if_ports", None),
    )
    node.traversal.addr_bytes = node.addr_bytes

    # Log address.
    msg = fstr("Starting node = '{0}'", (node.addr_bytes,))
    if not out:
        log_p2p(msg, node.node_id[:8])

    # Save a dict version of the address fields.
    try:
        node.addr_map = parse_node_addr(node.addr_bytes)
    except asyncio.CancelledError:  # pylint: disable=try-except-raise
        raise
    except (ValueError, TypeError) as exc:
        log_exception()
        raise ValueError("Can't parse nodes p2p addr.") from exc

    # Attach the per-node loopback alias to every if_info. select_dest_ipr
    # uses dest_info["loopback"] when same_pc=True so cross-subnet
    # same-machine peers route via 127.0.0.0/8 instead of NIC IPs.
    enrich_addr_map_with_loopback(node.addr_map)


async def finalize_port_forwarding(node: Any, upnp_task: Optional[Any], out: bool, cout: Callable) -> None:
    """Await the background UPnP task and log whether forwarding and reachability succeeded."""
    if upnp_task:
        if out:
            cout("\tStarting UPnP forwarding...")

        # Cap UPnP discovery / port-forward at 8s -- on XP the SSDP
        # stack drags this out to 13-15s, which combined with the
        # other startup phases blows past the 30s wait_for budget
        # callers like asyncio.wait_for(Node().start(), timeout=30)
        # use, making node startup look like a hard timeout when it's
        # actually just slow UPnP. 8s is enough for a working router
        # on every other platform; failures degrade gracefully (no
        # forwarding -> reverse_connect fallback still works).
        try:
            upnp_ret = await asyncio.wait_for(upnp_task, timeout=8)
        except asyncio.TimeoutError:
            upnp_ret = None
            if out:
                cout("\t\tUPnP timed out after 8s; continuing without forwarding.")
        if upnp_ret:
            forward_success, reachable = upnp_ret
        else:
            forward_success = reachable = None

        # Output AFs and NICs where UPnP succeeded on.
        if forward_success or reachable:
            if out:
                cout("\t\tUPnP forwarded = ", forward_success)
            if out:
                cout("\t\tUPnP reachable = ", reachable)
        else:
            if out:
                cout("\t\tUPnP failed: reverse connect won't work.")


# ==========================================
# Phase: High-Level Services
# ==========================================
async def setup_nickname_service(node: Any) -> None:
    """Initialise the PNP nickname client and optionally register this node's ID.

    Skips the entire client construction when enable_nickname=False --
    Nickname's __await__ runs start() which tries to reach every PNP
    server and raises StartNodeNicknameFailed if none come up. On
    hosts whose TLS / network stack can't talk to those servers (e.g.
    Windows XP), that fail kills node startup outright even when the
    caller never intended to use nicknames. Tests that opt out via
    enable_nickname=False shouldn't pay that cost. nick_client is
    left None so put/get crash loudly if accidentally called.
    """
    if not node.conf.get("enable_nickname", True):
        node.nick_client = None
        return

    node.nick_client = await Nickname(
        node.sk,
        node.ifs,
        node.sys_clock,
    )

    # Keep a reference so the task is not garbage-collected mid-run.
    task = asyncio.create_task(async_wrap_errors(node.nickname(node.node_id)))
    node.resources.add_task(task)


async def setup_traversal_plugins(node: Any) -> None:
    """Discover and install all traversal plugins found under the plugins/ directory."""
    await load_plugins(node)
    log("traversal plugin_loaders: " + str(node.traversal.plugin_loaders))
