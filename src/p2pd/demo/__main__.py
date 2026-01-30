"""
code a function for is_node_reachable_over_mqtt for debugging

I did delete the thing that saves send msg tasks in the mqtt client
idk if thats relevant.

python3 -m p2pd.demo --pnp_server 0,4,10.0.1.204,5300 --cmd 0dl4 --dest_addr 5b5ed965936a5f28c2795724a.p2p --echo "hello world"

python3 -m p2pd.demo --disable_upnp 1 --pnp_server 0,4,10.0.1.204,5300 --ip 10.0.1.230
python3 -m p2pd.demo --disable_upnp 1 --pnp_server 0,4,10.0.1.204,5300 --ip 10.0.1.19
"""

import asyncio
import signal
import os
from ..do_imports import *
from .defs import *
from .cmd_arg_defs import *
from .utils import *
from .cmd_arg_proc import *
from .menu import *
from ..node.node_defs import *

"""Load interfaces, start node, and return node info."""
async def setup_node():
    # Display program banner.
    cout(PROGRAM_BANNER)
    cout("pid = " + str(os.getpid()))

    # Load interfaces on machine.
    cout("Loading networking interfaces...")
    get_nickname = args.cmd == "get_nickname"
    if_names = await list_interfaces()
    print(if_names)

    ifs = await load_interfaces(
        if_names,
        Interface,
        min_agree=1,
        max_agree=2,
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
    print(stop_rw)
    node = Node(
        ifs=ifs, 
        ip=args.ip, 
        port=args.port, 
        stop_rw=stop_rw, 
        conf=demo_node_conf
    )

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
    except (StartNodeNicknameFailed, FullNameFailure):
        log_exception()
        cout("node id default nickname didnt load")
        cout("might have been taken over or all servers down.")
        cout("")

    nodes = [node]
    return nodes, ifs, nick

"""Run the main menu loop for node interaction."""
async def run_node_loop(nodes, ifs, nick):
    # Options for making a connection.
    # Set connection menu mode.
    menu_option = cmd_opts = None
    if args.cmd:
        menu_option = args.cmd[0]
        cmd_opts = args.cmd

    # Data to echo.
    echo_data = None
    if args.echo:
        echo_data = to_b(args.echo) + b"\n"

    # To simulate a "pointer" we exploit objects in Python are
    # passed by reference as use last_addr["addr"] as the pointer.
    last_addr = {}
    if args.dest_addr:
        last_addr = args.dest_addr

    # Show menu and choose option.
    con_opts = (last_addr, echo_data, cmd_opts,)
    while not sock_has_data(stop_rw[0]):
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
                return

        # Watch for connection errors.
        except TunnelFailed:
            cout("Tunnel connection failed!")

"""
Run the main program which accepts input and shows menu options.
Also waits for close events and handles cleanup.
"""
async def main():
    # Catch process exit signals (not supported on win32.)
    nodes = []
    if sys.platform != "win32":
        # Caught properly by async_run and wrapped catch.
        def set_shut_down():
            sock_has_data(stop_rw[1]).send(b"Shut down.")
            nodes[0].pp_executor.shutdown(wait=False)
            nodes[0].pp_executor = None


        # Install SIGTERM handler.
        loop = asyncio.get_event_loop()
        try:
            loop.add_signal_handler(signal.SIGTERM, set_shut_down)
        except NotImplementedError:
            log("This platform doesn't support sigterm handling.")

    # Start the program loop.
    try:
        # Setup node
        start_time = int(time.time())
        nodes, ifs, nick = await setup_node()
        if args.cmd == "get_nickname":
            print(nick)
            return

        # Start main loop task
        if args.run_time:
            log("run time argument applies = " + str(args.run_time))

            # Total execution time includes setup time.
            elapsed = int(time.time()) - start_time
            run_time = args.run_time - elapsed
            if run_time <= 0:
                return

            # Only execute program for this long.
            await asyncio.wait_for(
                run_node_loop(nodes, ifs, nick),
                timeout=run_time
            )
        else:
            await run_node_loop(nodes, ifs, nick)
    except asyncio.TimeoutError:
        log("Command run time met.")
        what_exception()
    except asyncio.CancelledError:
        log("Main task cancelled!")
        log_exception()
        what_exception()
    finally:
        log("stop nodes clause reached.")
        what_exception()

        # Stop all nodes
        if nodes:
            try:
                await stop_nodes_option(nodes)
            except asyncio.CancelledError:
                # ignore cancellation during cleanup
                pass

            del nodes[:]

        log("end of stop nodes clause.")

if __name__ == "__main__":
    try:
        async_run(main())
        log("main task done.")
    except KeyboardInterrupt:
        print("keyboard interrupt")
        log("keyboard interrupt clause reached.")
        print("ended")
    finally:
        # Force exit to prevent Windows from hanging on dead threads
        sys.exit(0)