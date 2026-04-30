"""
code a function for is_node_reachable_over_mqtt for debugging

I did delete the thing that saves send msg tasks in the mqtt client
idk if thats relevant.

python3 -m p2pd.demo --pnp_server 0,4,10.0.1.204,5300 --cmd 0dl4 \
    --dest_addr 5b5ed965936a5f28c2795724a.p2p --echo "hello world"

python3 -m p2pd.demo --disable_upnp 1 \
    --pnp_server 0,4,10.0.1.204,5300 --ip 10.0.1.230
python3 -m p2pd.demo --disable_upnp 1 \
    --pnp_server 0,4,10.0.1.204,5300 --ip 10.0.1.19

python3 -m p2pd.demo --disable_upnp 1 --nic 000c2957d05c
python3 -m p2pd.demo --disable_upnp 1 --nic ens34
"""

from typing import Any, List, Optional, Tuple
import asyncio
import time
import signal
import os
from aionetiface import (
    Interface,
    StartNodeNicknameFailed, TunnelFailed,
    async_run, async_wrap_errors, find_intersect, fstr,
    list_interfaces, load_interfaces, log, log_exception,
    sock_has_data, sys, to_b, to_s,
)
from ..node.nickname import FullNameFailure
from ..node.node import Node
from . import stop_rw
from .defs import MENU_BANNER, PROGRAM_BANNER, demo_node_conf
from .cmd_arg_defs import args
from .utils import (
    add_echo_support, ainput_interrupt_w, cout,
    display_ifs_loaded, filter_nics_by_mac,
)
from .menu import run_menu_program, stop_nodes_option

# Load interfaces, start node, and return node info.


async def setup_node() -> Tuple[List[Any], List[Any], Optional[str]]:
    """Load network interfaces, start the P2P node, and register a default nickname."""
    # Display program banner.
    cout(PROGRAM_BANNER)
    cout("pid = " + str(os.getpid()))

    # Load interfaces on machine.
    cout("Loading networking interfaces...")
    if_names = await list_interfaces()
    nic_arg = list(args.nic) if args.nic else []
    name_matched = False
    if args.nic:
        filtered_nics = list(find_intersect(if_names, args.nic))
        if filtered_nics:
            if_names = filtered_nics
            args.nic = []
            name_matched = True

    ifs = []
    for attempt in range(3):
        ifs = await load_interfaces(
            if_names, Interface, min_agree=1, max_agree=2, timeout=4
        )
        candidate = filter_nics_by_mac(args.nic, ifs) if args.nic else ifs
        if candidate:
            ifs = candidate
            args.nic = []
            break
        if name_matched:
            raise RuntimeError(
                "NIC '{0}' was found by name but failed to load. "
                "Check the interface is up and has a valid IP.".format(
                    ", ".join(str(n) for n in nic_arg)
                )
            )
        if attempt < 2:
            cout("No interfaces found (attempt {0}/3); retrying in 5 s...".format(attempt + 1))
            await asyncio.sleep(5)
    else:
        raise ValueError("Failed to load interfaces.")

    # Show the ifs loaded.
    display_ifs_loaded(ifs)

    # Main node class with chosen ifs and conf.
    # print(stop_rw)
    node = None
    for start_attempt in range(3):
        node = Node(
            ifs=ifs, ip=args.ip, port=args.port, stop_rw=stop_rw,
            conf=demo_node_conf, node_name=args.node_id,
        )

        # Start the node and install echo protocol handler.
        cout(fstr("Starting node on {0}...", (node.listen_port,)))
        node.add_msg_cb(add_echo_support)
        try:
            await node.start(out=True, cout=cout)
            break
        except StartNodeNicknameFailed:
            await async_wrap_errors(node.close())
            if start_attempt < 2:
                cout("PNP servers unreachable (attempt {0}/3); retrying in 5 s...".format(start_attempt + 1))
                await asyncio.sleep(5)
    else:
        raise StartNodeNicknameFailed()
    # print(node.pp_executor)

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

    # Allow the freshly-put PNP record + MQTT subscription to propagate
    # across the configured PNP/MQTT servers before we advertise this
    # node as ready. Without this gap, a peer that resolves the nick
    # immediately after seeing the "Listen on PNP" line can race a
    # server that hasn't yet observed the put and silently hang in the
    # resolve step.
    await asyncio.sleep(8)

    nodes = [node]
    return nodes, ifs, nick


# Run the main menu loop for node interaction.


async def run_node_loop(nodes: List[Any], ifs: List[Any], nick: Optional[str]) -> None:
    """Drive the interactive menu loop until the user exits or a stop signal arrives."""
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
    if args.dest:
        last_addr = args.dest

    # Show menu and choose option.
    con_opts = (
        last_addr,
        echo_data,
        cmd_opts,
    )
    while not sock_has_data(stop_rw[0]):
        try:
            # Show menu choices.
            cout(MENU_BANNER)

            # Shows the main menu options.
            outcome = await run_menu_program(nick, ifs, nodes, con_opts, menu_option)

            # Watch for attempts to exit loop.
            outcome = outcome.lower().strip()
            if outcome == "exit":
                return

            # When invoked non-interactively via --cmd, run the requested
            # action exactly once. Looping the menu makes sense for the
            # interactive REPL but a scripted --cmd run was just three
            # connect attempts on a 120s budget in the matrix because
            # connect_option always returns "menu" -- not what anyone
            # who passes --cmd expects.
            if args.cmd:
                return

        # Watch for connection errors.
        except TunnelFailed:
            cout("Tunnel connection failed!")


# Run the main program which accepts input and shows menu options.
# Also waits for close events and handles cleanup.


async def main() -> None:
    """Entry point: set up signal handlers, start the node, and run the menu loop."""
    # Strict install verification when --verify_install is passed.
    # Runs before any sibling-touching logic so a stale aionetiface
    # (or any other repo) imported from outside the expected layout
    # surfaces immediately with a clear error, instead of producing a
    # silent KeyError on plugin lookup later. The non-strict logging
    # version runs unconditionally inside node_start.
    if args.verify_install:
        from ..install_check import verify_sibling_installs
        verify_sibling_installs(strict=True)

    # Catch process exit signals (not supported on win32.)
    nodes = []
    if sys.platform != "win32":

        def set_shut_down() -> None:
            """Send a shutdown signal to all waiting loops and unblock pending ainput calls."""
            # Signal the stop socket so the main loop exits.
            try:
                stop_rw[1].send(b"Shut down.")
            except OSError:
                pass

            # Unblock any ainput() call waiting in an executor thread.
            try:
                os.write(ainput_interrupt_w, b"\x01")
            except OSError:
                pass

            # Shut down the process-pool executor if the node is up yet.
            if nodes:
                pp = getattr(nodes[0], "pp_executor", None)
                if pp is not None:
                    try:
                        pp.shutdown(wait=False)
                    except RuntimeError:
                        pass
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
            await asyncio.wait_for(run_node_loop(nodes, ifs, nick), timeout=run_time)
        else:
            await run_node_loop(nodes, ifs, nick)
    except asyncio.TimeoutError:
        log("Command run time met.")
        # what_exception()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        log("stop nodes clause reached.")
        # what_exception()

        # Stop all nodes
        if nodes:
            try:
                await async_wrap_errors(stop_nodes_option(nodes))
            except asyncio.CancelledError:
                # ignore cancellation during cleanup
                pass

            del nodes[:]

        log("end of stop nodes clause.")


if __name__ == "__main__":
    try:
        async_run(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass

    # Force exit to prevent Windows from hanging on dead threads.
    # Placed outside finally so cleanup in async_run() can finish first.
    sys.exit(0)
