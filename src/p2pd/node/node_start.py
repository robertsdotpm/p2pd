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
    load_cryptography_and_auth(node)

    # Connectivity Clients
    await load_p2p_stun_clients(node, out, cout)
    sig_pipes = await load_p2p_signal_pipes(node, out, cout)

    # Time & Synchronization
    await initialize_system_clock(node, sys_clock, out, cout)
    await initialize_punch_coordination(node, out, cout)

    # Start Servers
    start_maintenance_tasks(node)
    await node.listen_on_ifs()
    
    # Finalize Connectivity
    await finalize_port_forwarding(node, upnp_task, out, cout)
    build_node_address(node, sig_pipes, out)

    # High-Level Services
    await setup_nickname_service(node)
    setup_signal_router(node, sig_pipes)
    setup_traversal_plugins(node)

    return node

# ==========================================
# Phase: Hardware & Network Setup
# ==========================================
async def load_network_interfaces(node):
    if not len(node.ifs):
        print("\tLoading networking interfaces again...")
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
    
    print(node.ifs)

def load_cryptography_and_auth(node):
    install_path = node.conf["install_path"] or get_aionetiface_install_root()
    node.sk = load_signing_key(node.ifs, node.listen_ips, node.listen_port, install_path)
    node.vk = node.sk.verifying_key

    node.node_id = hashlib.sha256(
        node.vk.to_string("compressed")
    ).hexdigest()[:25]
    print(node.node_id)

    # Table of authenticated users
    node.auth = {
        node.node_id: {
            "sk": node.sk,
            "vk": node.vk.to_string("compressed"),
        }
    }

# ==========================================
# Phase: Connectivity Clients
# ==========================================
async def load_p2p_stun_clients(node, out, cout):
    if node.conf.get("enable_punching", True):
        if out: cout("\tLoading STUN clients...")
        # Returns TCP STUN clients using PUNCH_CONF.
        await load_stun_clients(node)
        
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
    
    print(node.stun_clients)

async def load_p2p_signal_pipes(node, out, cout):
    sig_pipes = []
    if node.conf["sig_pipe_no"]:
        if out: cout("\tLoading MQTT clients...")

        nic_afs = get_nic_for_af(node.ifs)
        # TODO -- limit to one for testing
        if IP6 in nic_afs:
            del nic_afs[IP6] 

        for af in nic_afs:
            nic = nic_afs[af]
            if not nic:
                continue
            print(af)
            sig_pipes += await load_signal_pipes(
                af, 
                nic, 
                node.node_id, 
                1 or node.conf["sig_pipe_no"] # TODO -- limit to 1 for testing
            )

        print(sig_pipes)

        if out:
            # Note: This logic assumes node.signal_pipes might be populated elsewhere 
            # or relies on the loop logic in the original. 
            buf = "\t\tmqtt = ("
            for index in list(node.signal_pipes):
                buf += fstr("{0},", (index,))
            buf += ")"
            cout(buf)
            
    return sig_pipes

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

def build_node_address(node, sig_pipes, out):
    assert(node.node_id is not None)
    
    sig_dests = [[af_to_v(s.af), s.host, s.port] for s in sig_pipes]
    print(sig_dests)

    node.addr_bytes = make_node_addr(
        node.node_id,
        node.machine_id,
        node.ifs,
        sig_dests,
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
        asyncio.create_task(
            node.nickname(node.node_id)
        )

def setup_signal_router(node, sig_pipes):
    node.signal_router = SignalRouter(
        node.ifs,
        node.sys_clock.time,
        node.node_id,
        node.addr_bytes,
        node.sk,
        SIG_PROTO
    )

    # Sets up the signaling router to use MQTT clients.
    node.signal_router.set_signal_pipes(sig_pipes)

    # Allow signaling router to pass messages to interested plugins.
    node.signal_router.set_traversal_manager(node.traversal)

    # Tell the traversal plugin manager how to send signal messages.
    node.traversal.set_signal_msg_sender(
        node.signal_router.signal_msg_sender
    )

def setup_traversal_plugins(node):
    node.traversal.install_plugin("punch", {
        "class": PunchPluginFactory(
            node.stun_clients,
            node.punch_clients,
            node.sys_clock,
            node.pp_executor,
        ),
        "timeout": 40
    })
    
    print(node.traversal.plugin_loaders)