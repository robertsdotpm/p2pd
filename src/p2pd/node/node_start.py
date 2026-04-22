"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""

import asyncio
import hashlib
import time
from aionetiface import *
from sidewire import *
from .node_utils import *
from .nickname import *
from ..traversal.traversal_address import *
from ..traversal.traversal_manager import TraversalManager
from ..traversal.plugins.punch.main import PunchPluginFactory
from ..traversal.plugins.turn.main import TURNPluginFactory
from .node_connect import install_default_plugins


# ==========================================
# Orchestrates the startup sequence for a P2P node.
# ==========================================
async def node_start(node, sys_clock=None, out=False, cout=print):
    # type: (Any, Optional[Any], bool, Callable) -> Any
    """Execute the full ordered startup sequence for a P2P node and return it when ready."""
    # Hardware & Network Setup
    await load_network_interfaces(node)
    upnp_task = start_background_port_forwarding(node)

    # Identity & Security
    await load_machine_identity(node)
    kp = load_cryptography_and_auth(node)

    # Time & Synchronization [concurrent Phase A]
    # Clock initialization, STUN client loading, and router startup all do network I/O;
    # run them concurrently for faster startup.
    await asyncio.gather(
        initialize_system_clock(node, sys_clock, out, cout),
        load_p2p_stun_clients(node, out, cout),
        setup_router_and_signal(node, kp, out, cout),
    )

    # Connectivity Clients
    node.router.get_time = node.sys_clock.time
    await initialize_punch_coordination(node, out, cout)

    # Start Servers
    start_maintenance_tasks(node)
    await listen_on_ifs(node)

    # Finalize Connectivity
    build_node_address(node, out)
    await finalize_port_forwarding(node, upnp_task, out, cout)

    # High-Level Services
    await setup_nickname_service(node)
    await setup_traversal_plugins(node)

    return node


# ==========================================
# Phase: Hardware & Network Setup
# ==========================================
async def load_network_interfaces(node):
    # type: (Any) -> None
    """Discover and sort all available network interfaces, raising RuntimeError if none are found."""
    if not len(node.ifs):
        try:
            if_names = await list_interfaces()
            node.ifs = await load_interfaces(if_names, Interface)
        except asyncio.CancelledError:
            raise
        except (OSError, asyncio.TimeoutError):
            log_exception()
            node.ifs = []

    # Ensure deterministic order
    node.ifs = sorted(node.ifs, key=lambda x: x.name)

    if not len(node.ifs):
        raise RuntimeError("p2p node could not load ifs.")


def start_background_port_forwarding(node):
    # type: (Any) -> Optional[Any]
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

        async def reachability_cb(msg, client_tup, pipe):
            # type: (Any, Any, Any) -> None
            """Forward inbound messages to the shared reachability checker."""
            await remote_reachability_cb(reachability, msg, client_tup, pipe)

        node.add_msg_cb(reachability_cb)

        return asyncio.create_task(
            async_wrap_errors(forward(node, node.listen_port, reachability), timeout=10)
        )
    return None


# ==========================================
# Phase: Identity & Security
# ==========================================
async def load_machine_identity(node):
    # type: (Any) -> None
    """Load or derive a stable machine ID and set the node's listen port deterministically."""
    node.machine_id = await load_machine_id("p2pd", node.ifs[0].netifaces)

    if node.machine_id in (None, ""):
        raise RuntimeError("Could not load machine id.")

    # The listen port is set deterministically to avoid conflicts
    # with port forwarding with multiple nodes in the LAN.
    if node.listen_port is None:
        node.listen_port = field_wrap(dhash(node.machine_id), [10000, 60000])


def load_cryptography_and_auth(node):
    # type: (Any) -> Any
    """Load or generate the node's ECDSA signing key, derive the node ID, and return the keypair."""
    install_path = resolve_install_path(node.conf)
    node.sk = load_signing_key(
        node.ifs, node.listen_ips, node.listen_port, install_path
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
async def initialize_system_clock(node, sys_clock, out, cout):
    # type: (Any, Optional[Any], bool, Callable) -> None
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


async def load_p2p_stun_clients(node, out, cout):
    # type: (Any, bool, Callable) -> None
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


async def setup_router_and_signal(node, kp, out, cout):
    # type: (Any, Any, bool, Callable) -> None
    """Instantiate the MQTT router, install default traversal plugins, and start the signal channel."""
    router = Router(kp, nic=Interface("default"))
    node.traversal = TraversalManager(
        router, node.stop_reader, node.inbound_pipes, node.ifs
    )
    install_default_plugins(node)
    router.add_msg_handler(node.traversal.recv_signal_msg)

    node.traversal.kp = node.kp

    await setup_signal_router(node, router, out, cout)


async def setup_signal_router(node, router, out, cout):
    # type: (Any, Any, bool, Callable) -> None
    """Attach the router to the node and start MQTT subscriptions for inbound signalling."""
    node.router = router

    # Subscribe to our own MQTT topic so we can receive incoming signals.
    if out:
        cout("\tLoading MQTT router...")
    try:
        clients = await asyncio.wait_for(router.start(), timeout=8)
        if out:
            cout("\t\t", clients)
    except asyncio.TimeoutError:
        raise RuntimeError("Router MQTT start timed out - signaling may be degraded")


# ==========================================
# Phase: Connectivity Clients
# ==========================================
async def initialize_punch_coordination(node, out, cout):
    # type: (Any, bool, Callable) -> None
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
def start_maintenance_tasks(node):
    # type: (Any) -> None
    """Launch the background idle-pipe-closer loop and register it for cancellation on shutdown."""
    # Simple loop to close idle tasks.
    node.resources.set_idle_closer(create_task(close_idle_pipes(node)))


# ==========================================
# Phase: Finalize Connectivity
# ==========================================
def build_node_address(node, out):
    # type: (Any, bool) -> None
    """Serialise the node's public key and interface info into addr_bytes and parse it into addr_map."""
    if node.node_id is None:
        raise RuntimeError("node_id was not set before building node address.")

    node.addr_bytes = make_node_addr(
        node.kp.public_key_hex,
        node.machine_id,
        node.ifs,
        port=node.listen_port,
    )
    node.traversal.addr_bytes = node.addr_bytes

    # Log address.
    msg = fstr("Starting node = '{0}'", (node.addr_bytes,))
    if not out:
        log_p2p(msg, node.node_id[:8])

    # Save a dict version of the address fields.
    try:
        node.addr_map = parse_node_addr(node.addr_bytes)
    except asyncio.CancelledError:
        raise
    except (ValueError, TypeError):
        log_exception()
        raise RuntimeError("Can't parse nodes p2p addr.")


async def finalize_port_forwarding(node, upnp_task, out, cout):
    # type: (Any, Optional[Any], bool, Callable) -> None
    """Await the background UPnP task and log whether forwarding and reachability succeeded."""
    if upnp_task:
        if out:
            cout("\tStarting UPnP forwarding...")

        upnp_ret = await upnp_task
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
async def setup_nickname_service(node):
    # type: (Any) -> None
    """Initialise the PNP nickname client and optionally register this node's ID."""
    node.nick_client = await Nickname(
        node.sk,
        node.ifs,
        node.sys_clock,
    )

    if node.conf.get("enable_nickname", True):
        # Keep a reference so the task is not garbage-collected mid-run.
        task = asyncio.create_task(node.nickname(node.node_id))
        node.resources.add_task(task)


async def setup_traversal_plugins(node):
    # type: (Any) -> None
    """Create and register the TCP punch and TURN relay plugin factories with the traversal manager."""
    if node.conf.get("enable_punching", True):
        punch_factory = await PunchPluginFactory.create(
            node.stun_clients, node.sys_clock
        )
        node.resources.punch_factory = punch_factory
        node.resources.register(punch_factory)
        node.traversal.install_plugin("punch", {"class": punch_factory, "timeout": 40})

    turn_factory = TURNPluginFactory(node.msg_cb, node.node_id)
    node.resources.register(turn_factory)
    node.traversal.install_plugin("turn", {"class": turn_factory, "timeout": 20})

    log("traversal plugin_loaders: " + str(node.traversal.plugin_loaders))
