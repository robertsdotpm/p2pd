import asyncio
from aioconsole import ainput
from ..do_imports import *
from .defs import *
from .utils import *

# Open a tunnel to a remote destination.
# Accepts a PNP address or a full node address.
async def connect_option(node, con_opts):
    # Some variables set by command line flags or other parts.
    last_addr, echo_data, cmd_opts = con_opts
    con_method = pathway = addr_type = None
    if cmd_opts:
        _, con_method, pathway, addr_type = cmd_opts

    # Dest addr is already set from command line.
    if type(last_addr) == str:
        dest_addr = last_addr
    else:
        dest_addr = await get_dest_addr(last_addr)

    # Get connect cmd segments manually if not set.
    strats = await choose_connection_methods(con_method)
    addr_types = await choose_pathways(pathway)
    af_priority = await choose_address_families(addr_type)
    if "menu" in (strats, addr_types, strats,):
        return "menu"

    # Data structure to control a tunnel to the remote host.
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
        if pipe is None:
            raise TunnelFailed("Connection failed.")
        return await echo_client(pipe, echo_data)
    finally:
        if pipe:
            await pipe.close()

    # Return to menu for unexpected code paths.
    return "menu"

async def accept_option(nick):
    print("Listen on PNP: \n", nick, flush=True)
    while 1:
        await asyncio.sleep(1)

    return "menu"

async def nickname_option(node):
    choice = await ainput("Enter nickname: ")
    try:
        ret = await node.nickname(choice)
        cout(fstr("Nickname registered = {0}", (str(ret),)))
    except:
        cout("Nickname taken.")
    
    return "menu"

async def node_spawn_option(ifs, nodes):
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

    return "menu"

async def stop_nodes_option(nodes):
    cout("")
    cout("Stopping nodes...")
    for n in nodes:
        await n.close()

    return ""

async def run_menu_program(nick, ifs, nodes, con_opts=None, menu_option=None):
    # Select menu program.
    menu_option = menu_option or (await ainput("Select menu option: "))
    menu_option = menu_option.lower().strip()
    
    # Connect to a remote host using PNP or full node address.
    if "connect:" and menu_option == "0":
        assert(con_opts)
        return (await connect_option(nodes[0], con_opts))

    # Just run the event loop so cons can be accepted.
    # Just an asyncio sleep loop.
    if "accept:" and menu_option == "1":
        # NOTE: Blocking loop so won't return.
        return (await accept_option(nick))
    
    # Create a new node for testing.
    # TODO: copy MQTT servers from node 0 to spawned node too.
    if "spawn:" and menu_option == "2":
        return (await node_spawn_option(ifs, nodes))

    # Set a new nickname for the primary node.
    if "nickname:" and menu_option == "3":
        return (await nickname_option(nodes[0]))

    # Close all nodes and exit the program.
    if "exit:" and menu_option in ("4", "exit", "quit"):
        return "exit"
    
    # Try again.
    return "menu"

