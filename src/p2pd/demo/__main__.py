"""
code a function for is_node_reachable_over_mqtt for debugging

I did delete the thing that saves send msg tasks in the mqtt client
idk if thats relevant.

python3 -m p2pd.demo --pnp_server 0,4,10.0.1.204,5300 --cmd 0dl4 --dest_addr 5b5ed965936a5f28c2795724a.p2p --echo "hello world"
"""

from ..do_imports import *
from .defs import *
from .cmd_arg_defs import *
from .utils import *
from .cmd_arg_proc import *
from .menu import *

Log.log_p2p = patch_log_p2p

async def setup_node():
    """Load interfaces, start node, and return node info."""
    # Display program banner.
    cout(PROGRAM_BANNER)

    # Load interfaces on machine.
    cout("Loading networking interfaces...")
    get_nickname = args.cmd == "get_nickname"
    if_names = await list_interfaces()
    ifs = await load_interfaces(
        if_names,
        Interface,
        min_agree=1 if get_nickname else 2,
        max_agree=2 if get_nickname else 5,
        timeout=4
    )

    """
    If the NICs flag has been set then filter the interface list
    to match only the MAC addresses indicated.
    """
    if args.nics:
        ifs = filter_nics_by_mac(args.nics, ifs)

    # Show the ifs loaded.
    display_ifs_loaded(ifs)

    # Main node class with chosen ifs and conf.
    node = Node(ifs=ifs, conf=node_conf)
    if args.port:
        node.listen_port = args.port

    # Start the node and install echo protocol handler.
    cout("Starting node on %d..." % (node.listen_port,))
    node.add_msg_cb(add_echo_support)
    await node.start(out=True, cout=cout)

    # Show the nodes address and listen port.
    cout()
    cout(fstr("Node started = {0}", (to_s(node.addr_bytes),)))
    cout(fstr("Node port = {0}", (node.listen_port,)))

    # Get PNP address of the node being started.
    nick = None
    try:
        nick = await node.nickname(node.node_id)
        cout(fstr("Node nickname = {0}", (nick,)))
        cout()
    except:
        log_exception()
        cout("node id default nickname didnt load")
        cout("might have been taken over or all servers down.")

    return node, ifs, nick

async def run_node_loop(node, ifs, nick):
    """Run the main menu loop for node interaction."""
    nodes = [node]

    # Options for making a connection.
    # Set connection menu mode.
    menu_option = cmd_opts = None
    if args.cmd:
        menu_option = args.cmd[0]
        cmd_opts = args.cmd

    # Data to echo.
    echo_data = None
    if args.echo:
        echo_data = to_b(args.echo)

    # To simulate a "pointer" we exploit the fact that objects in Python are
    # passed by reference as use last_addr["addr"] as the pointer.
    last_addr = {}
    if args.dest_addr:
        last_addr = args.dest_addr

    # Show menu and choose option.
    con_opts = (last_addr, echo_data, cmd_opts,)
    while True:
        try:
            # Show menu choices.
            cout(MENU_BANNER)

            # Shows the main menu options.
            outcome = await run_menu_program(
                nick,
                ifs,
                nodes,
                con_opts,
                menu_option
            )

            # Watch for attempts to exit loop.
            outcome = outcome.lower().strip()
            if outcome == "exit":
                await stop_nodes_option(nodes)
                return

        # Watch for connection errors.
        except TunnelFailed:
            cout("Tunnel connection failed!")

async def main():
    node, ifs, nick = await setup_node()

    # Output the node's address then finish.
    if args.cmd == "get_nickname":
        print(nick)
        await node.close()
        return

    await run_node_loop(node, ifs, nick)

if __name__ == "__main__":
    async_run(main())
