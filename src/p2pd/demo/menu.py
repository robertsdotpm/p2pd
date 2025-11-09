import asyncio
from ..do_imports import *
from .defs import *
from .utils import *

async def connect_option(last_addr=None):
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
    cout("TCP: (d)irect, (r)everse, (p)unch; UDP: (t)urn or menu to ")
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