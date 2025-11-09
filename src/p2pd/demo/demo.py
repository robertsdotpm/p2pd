"""
code a function for is_node_reachable_over_mqtt for debugging

I did delete the thing that saves send msg tasks in the mqtt client
idk if thats relevant.

python3 -m p2pd.demo --pnp_server 0,4,10.0.1.204,5300 --cmd 0dl4 --dest_addr 5b5ed965936a5f28c2795724a.p2p --echo "hello world"
"""

import asyncio
from ..do_imports import *
from .defs import *
from .cmd_args import *

Log.log_p2p = patch_log_p2p

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

            



if __name__ == "__main__":
    async_run(main())