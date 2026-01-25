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
from ..protocol.signaling.signal_msgs import SIG_PROTO


async def node_start(node, sys_clock=None, out=False, cout=print):
    # Load ifs.
    if not len(node.ifs):
        #print("\tLoading networking interfaces again...")
        try:
            if_names = await list_interfaces()
            node.ifs = await load_interfaces(if_names, Interface)
        except asyncio.CancelledError:
            raise
        except Exception:
            log_exception()
            node.ifs = []

    # Make sure ifs are in the same order.
    node.ifs = sorted(node.ifs, key=lambda x: x.name)

    # Managed to load IFs?
    if not len(node.ifs):
        raise Exception("p2p node could not load ifs.")
    
    # Skip port forwarding if all NICs aren't behind NATs.
    all_open_internet = True
    for nic in node.ifs:
        if nic.nat["type"] != OPEN_INTERNET:
            all_open_internet = False
            break
    
    # Port forward all listen servers.
    upnp_task = None
    if node.conf["enable_upnp"] and not all_open_internet:
        # Handler detects packets from test server.
        # To confirm if UPnP worked.
        node.add_msg_cb(node.remote_reachability_cb)

        # Put slow forwarding task in the background.
        upnp_task = asyncio.create_task(
            async_wrap_errors(
                node.forward(node.listen_port),
                timeout=10
            )
        )

    # Set machine id.
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
    install_path = node.conf["install_path"] or get_aionetiface_install_root()
    node.sk = load_signing_key(node.listen_ips, node.listen_port, install_path)
    node.vk = node.sk.verifying_key
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
                #buf += "\n"
            cout(buf)

    print(node.stun_clients)

    # MQTT server offsets for signal protocol.
    sig_pipes = []
    if node.conf["sig_pipe_no"]:
        if out: cout("\tLoading MQTT clients...")

        nic_afs = get_nic_for_af(node.ifs)
        del nic_afs[IP6] # TODO -- limit to one for testing
        for af in nic_afs:
            nic = nic_afs[af]
            print(af)
            sig_pipes += await load_signal_pipes(
                af, 
                nic, 
                node.node_id, # node.node_id # TODO -- fixed to same seed for testing
                1 or node.conf["sig_pipe_no"] # TODO -- limit to 1 for testing
            )

        print(sig_pipes)


        if out:
            buf = "\t\tmqtt = ("
            for index in list(node.signal_pipes):
                buf += fstr("{0},", (index,))
            buf += ")"
            cout(buf)

    if sys_clock is None:
        if node.conf["init_clock_skew"]:
            sys_clock = SysClock(
                interface=node.ifs[0]
            )
            await sys_clock.start()
        else:
            sys_clock = SysClock(node.ifs[0], ntp=time.time())
            node.sys_clock = sys_clock

    # Multiprocess support for TCP punching and NTP sync.
    t = time.time()
    if out: cout("\tLoading NTP clock skew...")
    if node.conf["enable_punching"]:
        await setup_punch_coordination(node, sys_clock)

    if node.conf["init_clock_skew"]:
        ntp = str(node.sys_clock.ntp)
        if out: cout(fstr("\t\tClock ntp = {0}", (ntp,)))

    # Simple loop to close idle tasks.
    node.idle_pipe_closer = create_task(
        close_idle_pipes(node)
    )

    # Start the server for the node protocol.
    await node.listen_on_ifs()

    # Port forward all listen servers.
    if node.conf["enable_upnp"] and not all_open_internet:
        if out: cout("\tStarting UPnP forwarding...")

        # Put slow forwarding task in the background.
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

    # Build P2P address bytes.
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

    # Used for setting nicknames for the node.
    node.nick_client = await Nickname(
        node.sk,
        node.ifs,
        node.sys_clock,
    )
    
    # Update nickname in the background.
    if node.conf.get("enable_nickname", True):
        nick = asyncio.create_task(
            node.nickname(node.node_id)
        )
        #pkt = await node.nick_client.fetch(nick)
        #cout("nick pkt vkc = ", pkt.vkc)

    # Used for sending signaling messasges to other nodes.
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

    # Used to create new punch plugin instances.
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

    return node