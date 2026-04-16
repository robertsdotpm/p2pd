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
from ..traversal.plugins.punch.main import PunchPluginFactory 
from ..protocol.traversal.proto_msg import SIG_PROTO

# ==========================================
# Orchestrates the startup sequence for a P2P node.
# ==========================================
async def node_start(node, sys_clock=None, out=False, cout=print):
    # Hardware & Network Setup
    await load_network_interfaces(node)
    upnp_task = start_background_port_forwarding(node)

    # Identity & Security
    await load_machine_identity(node)
    kp = load_cryptography_and_auth(node)
    print("pub key hex = ", kp.public_key_hex)

    # Time & Synchronization
    await initialize_system_clock(node, sys_clock, out, cout)
    await initialize_punch_coordination(node, out, cout)

    # Connectivity Clients
    await load_p2p_stun_clients(node, out, cout)
    traversal = node.traversal
    router = Router(kp, 
        msg_handler=traversal.handle_router_msg,
        get_time=node.sys_clock.time, 
        nic=Interface("default")
    )


    # Start Servers
    start_maintenance_tasks(node)
    await node.listen_on_ifs()
    
    # Finalize Connectivity
    await finalize_port_forwarding(node, upnp_task, out, cout)
    build_node_address(node, out)

    # High-Level Services
    await setup_nickname_service(node)
    await setup_signal_router(node, router, out, cout)
    setup_traversal_plugins(node)

    return node

# ==========================================
# Phase: Hardware & Network Setup
# ==========================================
async def load_network_interfaces(node):
    if not len(node.ifs):
        try:
            if_names = await list_interfaces()
            node.ifs = await load_interfaces(if_names, Interface)
        except asyncio.CancelledError:
            raise
        except Exception:
            log_exception()
            node.ifs = []

    # Ensure deterministic order
    node.ifs = sorted(node.ifs, key=lambda x: x.name)

    print(node.ifs)
    if not len(node.ifs):
        raise Exception("p2p node could not load ifs.")

def start_background_port_forwarding(node):
    # Check if all NICs are already open
    all_open_internet = True
    for nic in node.ifs:
        if nic.nat["type"] != OPEN_INTERNET:
            all_open_internet = False
            break
    
    # If UPnP is enabled and we are behind NAT, start the task
    if node.conf["enable_upnp"] and not all_open_internet:
        # Handler detects packets from test server to confirm if UPnP worked
        node.add_msg_cb(node.remote_reachability_cb)

        # Return the task so we can await it later
        return asyncio.create_task(
            async_wrap_errors(
                node.forward(node.listen_port),
                timeout=10
            )
        )
    return None

# ==========================================
# Phase: Identity & Security
# ==========================================
async def load_machine_identity(node):
    node.machine_id = await node.load_machine_id(
        "p2pd",
        node.ifs[0].netifaces
    )

    if node.machine_id in (None, ""):
        raise Exception("Could not load machine id.")

    # The listen port is set deterministically to avoid conflicts
    # with port forwarding with multiple nodes in the LAN.
    if node.listen_port is None:
        node.listen_port = field_wrap(
            dhash(node.machine_id),
            [10000, 60000]
        )

def load_cryptography_and_auth(node):
    install_path = node.conf["install_path"] or get_aionetiface_install_root()
    node.sk = load_signing_key(node.ifs, node.listen_ips, node.listen_port, install_path)
    node.vk = node.sk.verifying_key

    node.node_id = hashlib.sha256(
        node.vk.to_string("compressed")
    ).hexdigest()[:25]

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
# Phase: Connectivity Clients
# ==========================================
async def load_p2p_stun_clients(node, out, cout):
    if node.conf.get("enable_punching", True):
        if out: cout("\tLoading STUN clients...")
        # Returns TCP STUN clients using PUNCH_CONF.
        node.stun_clients = await load_stun_clients(node.ifs)

        if out:
            buf = ""
            for if_index in range(0, len(node.ifs)):
                nic = node.ifs[if_index]
                buf += "\t\t" + nic.name + " "
                for af in nic.supported():
                    af_txt = "V4" if af is IP4 else "V6"
                    buf += fstr("({0}={1})", (
                        af_txt,
                        str(len(node.stun_clients[af][if_index])),
                    ))
            cout(buf)

# ==========================================
# Phase: Time & Synchronization
# ==========================================
async def initialize_system_clock(node, sys_clock, out, cout):
    if sys_clock is None:
        if node.conf["init_clock_skew"]:
            sys_clock = SysClock(
                interface=node.ifs[0]
            )
            await sys_clock.start()
        else:
            sys_clock = SysClock(node.ifs[0], ntp=time.time())
            node.sys_clock = sys_clock
    
    # Store reference if passed in or created
    if not hasattr(node, 'sys_clock') or node.sys_clock is None:
        node.sys_clock = sys_clock

async def initialize_punch_coordination(node, out, cout):
    if out: cout("\tLoading NTP clock skew...")
    
    # Multiprocess support for TCP punching and NTP sync.
    if node.conf["enable_punching"]:
        await setup_punch_coordination(node, node.sys_clock)

    if node.conf["init_clock_skew"]:
        ntp = str(node.sys_clock.ntp)
        if out: cout(fstr("\t\tClock ntp = {0}", (ntp,)))

# ==========================================
# Phase: Start Servers
# ==========================================
def start_maintenance_tasks(node):
    # Simple loop to close idle tasks.
    node.idle_pipe_closer = create_task(
        close_idle_pipes(node)
    )

# Note: node.listen_on_ifs() is called directly in main sequence

# ==========================================
# Phase: Finalize Connectivity
# ==========================================
async def finalize_port_forwarding(node, upnp_task, out, cout):
    if upnp_task:
        if out: cout("\tStarting UPnP forwarding...")

        upnp_ret = await upnp_task
        if upnp_ret:
            forward_success, reachable = upnp_ret
        else:
            forward_success = reachable = None

        # Output AFs and NICs where UPnP succeeded on.
        if forward_success or reachable:
            if out: cout("\t\tUPnP forwarded = ", forward_success)
            if out: cout("\t\tUPnP reachable = ", reachable)
        else:
            if out: cout("\t\tUPnP failed: reverse connect won't work.")

def build_node_address(node, out):
    if node.node_id is None:
        raise RuntimeError("node_id was not set before building node address.")

    node.addr_bytes = make_node_addr(
        node.kp.public_key_hex,
        node.machine_id,
        node.ifs,
        port=node.listen_port,
    )

    # Log address.
    msg = fstr("Starting node = '{0}'", (node.addr_bytes,))
    if not out:
        log_p2p(msg, node.node_id[:8])

    # Save a dict version of the address fields.
    try:
        node.p2p_addr = parse_node_addr(node.addr_bytes)
    except asyncio.CancelledError:
        raise
    except Exception:
        log_exception()
        raise Exception("Can't parse nodes p2p addr.")


# ==========================================
# Phase: High-Level Services
# ==========================================
async def setup_nickname_service(node):
    node.nick_client = await Nickname(
        node.sk,
        node.ifs,
        node.sys_clock,
    )

    if node.conf.get("enable_nickname", True):
        # Keep a reference so the task is not garbage-collected mid-run.
        task = asyncio.create_task(
            node.nickname(node.node_id)
        )
        node.tasks.append(task)

async def setup_signal_router(node, router, out, cout):
    # Give the traversal manager a reference to the node so that
    # signal_msg_sender and handle_router_msg can access node state.
    node.router = router
    node.traversal.node = node
    router.traversal = node.traversal
    node.traversal.router = router

    # Subscribe to our own MQTT topic so we can receive incoming signals.
    if out: cout("\tLoading MQTT router...")
    try:
        clients = await asyncio.wait_for(router.start(), timeout=8)
        if out: cout("\t\t", clients)
    except asyncio.TimeoutError:
        raise Exception("Router MQTT start timed out - signaling may be degraded")

def setup_traversal_plugins(node):
    if node.conf.get("enable_punching", True):
        node.traversal.install_plugin("punch", {
            "class": PunchPluginFactory(
                node.stun_clients,
                node.punch_clients,
                node.sys_clock,
                node.pp_executor,
            ),
            "timeout": 40
        })

    log("traversal plugin_loaders: " + str(node.traversal.plugin_loaders))