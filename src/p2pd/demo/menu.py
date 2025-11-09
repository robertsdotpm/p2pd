import asyncio
from ..do_imports import *
from .defs import *
from .utils import *

async def connect_option(node, last_addr=None, echo_data=None):
    """
    Dest addr may have already been set from previous invocations of the program.
    It's designed to be interactive so you don't have to keep pasting the
    same address for a dest if you're trying to test a remote machine.
    """
    extra_txt = ""
    if len(last_addr):
        extra_txt = fstr("(enter for {0})", (last_addr,))

    # Enter to use the last address if it's set.
    dest_addr = input(fstr("Enter nodes nickname or address {0}: ", (extra_txt,)))
    if dest_addr == "":
        dest_addr = last_addr
    else:
        last_addr = dest_addr

    # Select a connection method segment.
    cout()
    cout("Connection methods (in order):")
    cout("TCP: (d)irect, (r)everse, (p)unch; UDP: (t)urn.")
    cout("Type menu to return.")
    strats = []
    while 1:
        # If pressing enter then use the default list of methods in order.
        con_method = con_method or input("Enter for default (drp): ")
        if not len(con_method):
            strats = P2P_STRATEGIES
            break

        # Go back to the menu.
        if con_method.lower().strip() == "menu":
            return "menu"

        # Save a list of only valid choices.
        strats = []
        for c in con_method:
            c = c.lower()
            if c in method_txt:
                strats.append(method_txt[c])

        # Try again if there are no valid choices.
        if not len(strats):
            continue
        else:
            break

    # Choose the routing pathway to try (this controls IP selection!)
    # This is why having accurate interface info is so important.
    cout()
    cout("Enabled connection pathways (in order):")
    cout("WAN: (e)xternal, LAN: (l)ocal ")
    cout("Type menu to return.")
    addr_types = []
    while 1:
        # Enter means try external then local.
        pathway = pathway or input("Enter for default (el): ")
        if not len(pathway):
            addr_types = [EXT_BIND, NIC_BIND]
            break

        # Go back to the menu.
        if con_method.lower().strip() == "menu":
            return "menu"

        # Same pattern as before: get a list of valid choices to order.
        addr_types = []
        for c in pathway:
            c  = c.lower()
            if c == 'e':
                addr_types.append(EXT_BIND)
            if c == 'l':
                addr_types.append(NIC_BIND)

        # If no valid choices then try again.
        if not len(addr_types):
            continue
        else:
            break

    # Allows the code to specifically use one or more address families.
    # Applicable / useful for duel-stack environments.
    cout()
    cout("Address family priority (in order):")
    cout("(4) IPv4, (6) IPv6")
    cout("Type menu to return.")
    af_priority = []
    while 1:
        # Bias to IPv4 first then try 6 if supported.
        # Both machines need to support the same address family.
        addr_type = addr_type or input("Enter for default (46): ")
        if not len(addr_type):
            af_priority = [IP4, IP6]
            break

        # Go back to the menu.
        if con_method.lower().strip() == "menu":
            return "menu"

        # Filter by valid choice.
        af_priority = []
        for c in addr_type:
            c  = c.lower()
            if c == '4':
                af_priority.append(IP4)
            if c == '6':
                af_priority.append(IP6)

        # Skip if there are none.
        if not len(af_priority):
            continue
        else:
            break

    # Data structure to control a tunnel to the remote host.
    # This is when connection options and address families are manually chosen.
    cout()
    cout("Connection in progress... Please wait...")
    pipe_conf = {
        "addr_types": addr_types,
        "addr_families": af_priority,
        "return_msg": False,
    }

    # Attempt to make the tunnel connection to the remote host.
    pipe = await node.connect(dest_addr, strategies=strats, conf=pipe_conf)
    try:
        # Failed to create connection to remote machine.
        if pipe is None:
            raise TunnelFailed("Connection failed.")
        else:
            # Tunnel is open -- interactive echo client can be used.
            cout("Connection open.")
            cout(pipe.sock)
            cout()
            cout("Basic echo protocol.")
            cout("Enter menu to return to menu or exit to quit.")
            while 1:
                # Allows a simple echo client over the tunnel for testing.
                send_buf = echo_data or to_b(input("Echo: "))
                if send_buf in (b"quit", b"exit"):
                    return "exit"

                # Go back to the main menu.
                if send_buf in (b"menu"):
                    send_buf = ""
                    return "menu"

                await pipe.send(b"ECHO " + send_buf + b"\n")
                buf = await pipe.recv(timeout=3)
                cout(b"recv = ", buf)
                if echo_data:
                    print(buf)
                    return "exit"
    finally:
        if pipe:
            await pipe.close()

    # Return to menu for unexpected code paths.
    return "menu"

async def accept_option():
    print("Listen on PNP: \n", nick)
    while 1:
        await asyncio.sleep(1)

async def nickname_option():
    choice = input("Enter nickname: ")
    try:
        ret = await node.nickname(choice)
        cout(fstr("Nickname registered = {0}", (str(ret),)))
    except:
        cout("Nickname taken.")

async def node_spawn_option():
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

async def stop_nodes_option():
    cout("Stopping nodes...")
    for n in nodes:
        await n.close()

async def show_menu_program():
    menu_option = menu_option or input("Select menu option: ")
    if menu_option not in ("0", "1", "2", "3", "4", "exit", "quit"):
        continue

    if menu_option in ("exit", "quit"):
        menu_option = "4"

    if menu_option == "1":
        accept_option

    if menu_option == "3":
        nickname_option

        continue

    # TODO: copy mqtt from alice too.
    # maybe dont bother port forwarding either
    if menu_option == "2":
        spawn_node_option
        continue

    if menu_option == "0":
        connect_option

    if menu_option == "4":
        exit_option
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