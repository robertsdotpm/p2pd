"""
code a function for is_node_reachable_over_mqtt for debugging

I did delete the thing that saves send msg tasks in the mqtt client
idk if thats relevant.

python3 -m p2pd.demo --pnp_server 0,4,10.0.1.204,5300 --cmd 0dl4 --dest_addr 5b5ed965936a5f28c2795724a.p2p --echo "hello world"
"""

import asyncio
import argparse
from .do_imports import *

IS_DEBUG = 2

node_conf = dict_child({
    "init_clock_skew": True,
    "reuse_addr": False,
    "enable_upnp": True,
    "sig_pipe_no": SIGNAL_PIPE_NO,
    "enable_punching": True,
    "enable_nickname": True,
    "enable_stun_clients": True,
    "install_path": get_p2pd_install_root()
}, NET_CONF)


parser = argparse.ArgumentParser(description="A simple greeting script")
parser.add_argument("--nics", type=str, required=False, help="Limit to specific nics, comma separated")
parser.add_argument("--port", type=int, required=False, help="Start node on specific port")
parser.add_argument("--pnp_server", type=str, required=False, help="Specify using a specific PNP server")
parser.add_argument("--turn_server", type=str, required=False, help="Specify using a specific TURN server")
parser.add_argument("--mqtt_server", type=str, required=False, help="Specify using a specific STUN server")
parser.add_argument("--dest_addr", type=str, required=False, help="Destination to connect to")
parser.add_argument("--echo", type=str, required=False, help="Text to send down the connection")
parser.add_argument("--cmd", type=str, required=False, help="Command to run")
parser.add_argument("--install_path", type=str, required=False, help="Directory path to use to store some of P2PDs data files. Defaults to user home/p2pd")
parser.add_argument("--disable_upnp", type=str, required=False, help="Disable port forwarding and IPv6 pin hole rules on an associated router?")
args = parser.parse_args()

if args.disable_upnp:
    node_conf["enable_upnp"] = False

"""
parser.add_argument("--stun_server", type=str, required=False, help="Specify using a specific STUN server")
parser.add_argument("--ntp_server", type=str, required=False, help="Specify using a specific STUN server")
"""

def get_req_serv_parts(parts):
    ip = parts[2]
    offset = int(parts[0])
    af = int(parts[1])
    port = int(parts[3])
    if af == 4:
        af = IP4
    else:
        af = IP6

    return offset, af, ip, port

def patch_server_af_dict(arg_list, serv_dict):
    # offset, af, ip, port
    if ";" in arg_list:
        serv_infos = arg_list.split(";")
    else:
        serv_infos = [arg_list]


    for serv_info in serv_infos:
        parts = serv_info.split(",")
        offset, af, ip, port = get_req_serv_parts(parts)
        serv_dict[af][offset]["host"] = ip
        serv_dict[af][offset]["ip"] = ip
        serv_dict[af][offset]["port"] = port
        if "afs" not in serv_dict:
            serv_dict["afs"] = []

def patch_server_list(arg_list, server_list):
    # offset, af, ip, port, (optional) user, (optional) password
    if ";" in arg_list:
        serv_infos = arg_list.split(";")
    else:
        serv_infos = [arg_list]

    for serv_info in serv_infos:
        parts = serv_info.split(",")
        offset, af, ip, port = get_req_serv_parts(parts)
        username = password = None
        if len(parts) >= 5:
            username = parts[4]
        if len(parts) >= 6:
            password = parts[5]

        if server_list[offset]["host"] != ip:
            entry = {
                "host": ip,
                "port": port,
                "user": username,
                "pass": password,
                IP4: None,
                IP6: None,
                "afs": []
            }
        else:
            entry = server_list[offset]

        entry[af] = ip
        entry["afs"].append(af)
        server_list[offset] = entry

if args.pnp_server:
    patch_server_af_dict(args.pnp_server, PNP_SERVERS)

if args.turn_server:
    patch_server_list(args.turn_server, TURN_SERVERS)

if args.mqtt_server:
    patch_server_list(args.mqtt_server, MQTT_SERVERS)

def cout(*fargs):
    if args.cmd:
        return
    else:
        if not len(fargs):
            print()
        else:
            print(*fargs)

def patch_log_p2p(m, node_id=""):
    out = fstr("p2p: <{0}> ", (node_id,)) + to_s(m)
    cout(out)

Log.log_p2p = patch_log_p2p

async def add_echo_support(msg, client_tup, pipe):
    if b"ECHO" == msg[:4]:
        cout()
        cout("\tGot echo proto msg: " + to_s(msg) + fstr(" from {0}", (client_tup,)))
        cout()
        await pipe.send(msg[4:], client_tup)

nat_txt = {
    OPEN_INTERNET: "open internet",
    SYMMETRIC_UDP_FIREWALL: "udp firewall",
    FULL_CONE: "full cone",
    RESTRICT_NAT: "restrict",
    RESTRICT_PORT_NAT: "restrict port",
    SYMMETRIC_NAT: "symmetric",
    BLOCKED_NAT: "blocked"
}

delta_txt = {
    NA_DELTA: "not applicable",
    EQUAL_DELTA: "equal",
    PRESERV_DELTA: "preserving",
    INDEPENDENT_DELTA: "independent",
    DEPENDENT_DELTA: "dependent",
    RANDOM_DELTA: "random"
}

method_txt = {
    "d": P2P_DIRECT,
    "r": P2P_REVERSE,
    "p": P2P_PUNCH,
    "t": P2P_RELAY,
}

async def main():
    cout("Universal reachability demo")
    cout("Coded by matthew@roberts.pm")
    cout("-----------------------------")
    cout()
    cout("Loading networking interfaces...")

    if_names = await list_interfaces()
    if args.cmd == "get_nickname":
        # Speed up interface loading for nickname only.
        ifs = await load_interfaces(
            if_names,
            Interface,
            1,
            2,
            skip_nat=True,
            timeout=8
        )
    else:
        ifs = await load_interfaces(
            if_names,
            Interface,
            timeout=4
        )

    """
    If the NICs flag has been set then filter the interface list
    to match only the MAC addresses indicated.
    """
    if args.nics:
        if "," in args.nics:
            mac_list = args.nics.split(",")
        else:
            mac_list = [args.nics]

        mac_list = [mac_norm(mac) for mac in mac_list]
        new_ifs = []
        for nic in ifs:
            if nic.mac in mac_list:
                new_ifs.append(nic)

        ifs = new_ifs

    buf = ""
    for nic in ifs:
        buf += fstr("\t{0} ", (nic.name,))
        for af in nic.supported():
            if af == IP4:
                buf += "(v4)"
            if af == IP6:
                buf += "(v6)"
        buf += fstr("\n\t\t{0} nat; ", (nat_txt[nic.nat['type']],))
        buf += fstr("{0} delta = ", (delta_txt[nic.nat['delta']['type']],))
        buf += fstr("{0}", (nic.nat['delta']['value'],))
        buf += "\n"
    cout(buf[:-1])

    if args.cmd == "get_nickname":
        node_conf["sig_pipe_no"] = 0
        node_conf["enable_upnp"] = False
        node_conf["init_clock_skew"] = False
        node_conf["enable_punching"] = False
        #node_conf["enable_nickname"] = False

    if args.install_path:
        node_conf["install_path"] = args.install_path

    node = Node(ifs=ifs, conf=node_conf)
    if args.port:
        node.listen_port = args.port

    cout("Starting node on %d..." % (node.listen_port,))
    nodes = []
    node.add_msg_cb(add_echo_support)
    await node.start(out=True, cout=cout)
    nodes.append(node)
    cout()
    cout(fstr("Node started = {0}", (to_s(node.addr_bytes),)))
    cout(fstr("Node port = {0}", (node.listen_port,)))


    nick = None
    try:
        nick = await node.nickname(node.node_id)
        cout(fstr("Node nickname = {0}", (nick,)))
        cout()
    except:
        log_exception()
        cout("node id default nickname didnt load")
        cout("might have been taken over or all servers down.")

    if args.cmd:
        if args.cmd == "get_nickname":
            print(nick)
            await node.close()
            return
        
    # Options for making a connection.
    # Set connection menu mode.
    menu_option = None
    con_method = pathway = addr_type = None
    if args.cmd:
        menu_option = args.cmd[0]
        if menu_option == "0":
            menu_option, con_method, pathway, addr_type = args.cmd

    # Connect to this destination.
    dest_addr = None
    if args.dest_addr:
        dest_addr = args.dest_addr

    # Allow piping an address to this program.
    """
    stdin_data = sys.stdin.read().strip()
    if stdin_data:
        lines = list(stdin_data)
        dest_addr = lines[0].rstrip("\n")
    """

    # Data to echo.
    echo_data = None
    if args.echo:
        echo_data = to_b(args.echo)

    cout(\
"""(0) Connect to a node using its nickname or address.
(1) Start accepting connections (this stops the input loop)
(2) Start additional node for testing (needed for self punch.)
(3) Register a unique nickname for your node.
(4) Exit program.
""")

    last_addr = ""
    choice = None
    while 1:
        menu_option = menu_option or input("Select menu option: ")
        if menu_option not in ("0", "1", "2", "3", "4", "exit", "quit"):
            continue

        if menu_option in ("exit", "quit"):
            menu_option = "4"

        if menu_option == "1":
            print("Listen on PNP: \n", nick)
            while 1:
                await asyncio.sleep(1)

        if menu_option == "3":
            choice = input("Enter nickname: ")
            try:
                ret = await node.nickname(choice)
                cout(fstr("Nickname registered = {0}", (str(ret),)))
            except:
                cout("Nickname taken.")

            continue

        # TODO: copy mqtt from alice too.
        # maybe dont bother port forwarding either
        if menu_option == "2":
            alice = nodes[-1]
            bob = Node(port=alice.listen_port + 1, ifs=ifs, conf=node_conf)
            bob.add_msg_cb(add_echo_support)
            bob.stun_clients = alice.stun_clients
            await asyncio.create_task(
                bob.start(sys_clock=alice.sys_clock, out=True)
            )
            cout()
            cout(fstr("New node addr = {0}", (to_s(bob.addr_bytes),)))
            ret = await bob.nickname(bob.node_id)
            cout(fstr("New node port = {0}", (bob.listen_port,)))
            cout(fstr("New node nickname = {0}", (ret,)))
            nodes.append(bob)
            cout()
            continue

        if menu_option == "0":
            if dest_addr is None:
                prefix = ""
                if len(last_addr):
                    prefix = fstr(" (enter for {0})", (last_addr,))

                dest_addr = input(fstr("Enter nodes nickname or address{0}: ", (prefix,)))
                if dest_addr == "":
                    dest_addr = last_addr
                else:
                    last_addr = dest_addr
            

            cout()
            cout("Connection methods (in order):")
            cout("TCP: (d)irect, (r)everse, (p)unch; UDP: (t)urn")
            strats = []
            while 1:
                con_method = con_method or input("Enter for default (drp): ")
                if not len(con_method):
                    strats = P2P_STRATEGIES
                    break

                strats = []
                for c in con_method:
                    c = c.lower()
                    if c in method_txt:
                        strats.append(method_txt[c])

                if not len(strats):
                    continue
                else:
                    break

            cout(strats)

            cout()
            cout("Enabled connection pathways (in order):")
            cout("WAN: (e)xternal, LAN: (l)ocal ")
            addr_types = []
            while 1:
                pathway = pathway or input("Enter for default (el): ")
                if not len(pathway):
                    addr_types = [EXT_BIND, NIC_BIND]
                    break

                addr_types = []
                for c in pathway:
                    c  = c.lower()
                    if c == 'e':
                        addr_types.append(EXT_BIND)
                    if c == 'l':
                        addr_types.append(NIC_BIND)

                if not len(addr_types):
                    continue
                else:
                    break

            cout()
            cout("Address family priority (in order):")
            cout("(4) IPv4, (6) IPv6")
            af_priority = []
            while 1:
                addr_type = addr_type or input("Enter for default (46): ")
                if not len(addr_type):
                    af_priority = [IP4, IP6]
                    break

                af_priority = []
                for c in addr_type:
                    c  = c.lower()
                    if c == '4':
                        af_priority.append(IP4)
                    if c == '6':
                        af_priority.append(IP6)

                if not len(af_priority):
                    continue
                else:
                    break

            cout()
            cout("Connection in progress... Please wait...")
            pipe_conf = {
                "addr_types": addr_types,
                "addr_families": af_priority,
                "return_msg": False,
            }

            pipe = await node.connect(dest_addr, strategies=strats, conf=pipe_conf)
            if pipe is None:
                cout("Connection failed.")
                continue
            else:
                cout("Connection open.")
                cout(pipe.sock)
                cout()
                cout("Basic echo protocol.")
                cout("Enter menu to return to menu or exit to quit.")
                while 1:
                    echo_data = echo_data or to_b(input("Echo: "))
                    if echo_data in (b"quit", b"exit"):
                        echo_data = "4"
                        break
                    if echo_data in (b"menu"):
                        echo_data = ""
                        await pipe.close()
                        break

                    await pipe.send(b"ECHO " + echo_data + b"\n")
                    buf = await pipe.recv(timeout=3)
                    cout(b"recv = ", buf)
                    if args.echo:
                        print(buf)
                        menu_option = "4"
                        break

        if menu_option == "4":
            cout("Stopping nodes...")
            for n in nodes:
                await n.close()
            return

        """
        if choice == "4":
            if addr is None:
                prefix = ""
                if len(last_addr):
                    prefix = fstr(" (enter for {0})", (last_addr,))

                addr = input(fstr("Enter nodes nickname or address{0}: ", (prefix,)))
                if addr == "":
                    addr = last_addr
                else:
                    last_addr = addr
        """
            



if __name__ == "__main__":
    async_run(main())