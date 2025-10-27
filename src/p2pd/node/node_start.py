"""
Note:
Reusing address can hide socket errors and
make servers appear broken when they're not.
"""
import asyncio
import hashlib
import time
from ..nic.interface import load_interfaces
from ..nic.select_interface import list_interfaces
from ..net.daemon import *
from .node_addr import *
from .node_utils import *
from .nickname import *
from ..traversal.tunnel_address import *
from ..traversal.signaling.signaling_protocol import *
from ..traversal.signaling.signaling_utils import *
from ..traversal.signaling.signaling_sender import *

async def node_start(node, sys_clock=None, out=False):
    # Load ifs.
    t = time.time()
    if not len(node.ifs):
        try:
            if_names = await list_interfaces()
            node.ifs = await load_interfaces(if_names, Interface)
        except:
            log_exception()
            node.ifs = []

    # Make sure ifs are in the same order.
    node.ifs = sorted(node.ifs, key=lambda x: x.name)

    # Managed to load IFs?
    if not len(node.ifs):
        raise Exception("p2p node could not load ifs.")

    # Set machine id.
    t = time.time()
    node.machine_id = await node.load_machine_id(
        "p2pd",
        node.ifs[0].netifaces
    )

    # Managed to load machine IDs?
    if node.machine_id in (None, ""):
        raise Exception("Could not load machine id.")
    
    """
    The listen port is set deterministically to avoid conflicts
    with port forwarding with multiple nodes in the LAN.
    """
    if node.listen_port is None:
        node.listen_port = field_wrap(
            dhash(node.machine_id),
            [10000, 60000]
        )

    # Cryptography for authenticated messages.
    node.sk = load_signing_key(node.listen_port)
    print("sk:", node.sk)

    node.vk = node.sk.verifying_key
    print("vk:", node.vk)

    node.node_id = hashlib.sha256(
        node.vk.to_string("compressed")
    ).hexdigest()[:25]

    # Table of authenticated users.
    node.auth = {
        node.node_id: {
            "sk": node.sk,
            "vk": node.vk.to_string("compressed"),
        }
    }

    # Used by TCP punch clients.
    t = time.time()
    if out: print("\tLoading STUN clients...")
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
            buf += "\n"
        print(buf)

    # MQTT server offsets for signal protocol.
    if node.conf["sig_pipe_no"]:
        if out: print("\tLoading MQTT clients...")
        await load_signal_pipes(node, node.node_id)
        if out:
            buf = "\t\tmqtt = ("
            for index in list(node.signal_pipes):
                buf += fstr("{0},", (index,))
            buf += ")"
            print(buf)

    if sys_clock is None:
        sys_clock = SysClock(
            interface=node.ifs[0]
        )
        await sys_clock.start()

    # Multiprocess support for TCP punching and NTP sync.
    t = time.time()
    if out: print("\tLoading NTP clock skew...")
    await setup_punch_coordination(node, sys_clock)
    clock_skew = str(node.sys_clock.clock_skew)
    if out: print(fstr("\t\tClock skew = {0}", (clock_skew,)))
        
    # Accept TCP punch requests.
    start_punch_worker(node)

    # Start worker that forwards sig proto messages.
    start_sig_msg_queue_worker(node)

    # Simple loop to close idle tasks.
    node.idle_pipe_closer = create_task(
        close_idle_pipes(node)
    )

    # Start the server for the node protocol.
    await node.listen_on_ifs()

    # Skip port forwarding if all NICs aren't behind NATs.
    all_open_internet = True
    for nic in node.ifs:
        if nic.nat["type"] != OPEN_INTERNET:
            all_open_internet = False
            break

    # Port forward all listen servers.
    if node.conf["enable_upnp"] and not all_open_internet:
        if out: print("\tStarting UPnP task...")

        # Put slow forwarding task in the background.
        forward = asyncio.create_task(
            node.forward(node.listen_port)
        )
        node.tasks.append(forward)
        await asyncio.sleep(2)

    # Build P2P address bytes.
    assert(node.node_id is not None)
    node.addr_bytes = make_peer_addr(
        node.node_id,
        node.machine_id,
        node.ifs,
        list(node.signal_pipes),
        port=node.listen_port,
    )

    # Log address.
    msg = fstr("Starting node = '{0}'", (node.addr_bytes,))
    if not out:
        Log.log_p2p(msg, node.node_id[:8])

    # Save a dict version of the address fields.
    try:
        self.p2p_addr = parse_peer_addr(node.addr_bytes)
    except:
        log_exception()
        raise Exception("Can't parse nodes p2p addr.")

    # Used for setting nicknames for the node.
    node.nick_client = await Nickname(
        node.sk,
        node.ifs,
        node.sys_clock,
    )

    nick = await node.nickname(node.node_id)
    print(nick)
    pkt = await node.nick_client.fetch(nick)
    print("nick pkt vkc = ", pkt.vkc)

    return node