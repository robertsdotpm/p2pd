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
    StartNodeNicknameFailed, SysClock, TunnelFailed,
    allow_windows_firewall,
    async_run, async_wrap_errors, fstr,
    list_interfaces, load_interfaces, log, log_exception,
    sock_has_data, sys, to_b, to_s,
)
from ..node.nickname import (
    FullNameFailure, PnpServerResourceLimit, PnpServerUnreachable,
)
from ..node.node import Node
from ..gate import Gate
from . import stop_rw
from .defs import MENU_BANNER, PROGRAM_BANNER, demo_node_conf
from .cmd_arg_defs import args
from .utils import (
    add_echo_support, ainput_interrupt_w, cout,
    display_ifs_loaded,
)
from .menu import run_menu_program, stop_nodes_option

# Load interfaces, start node, and return node info.


async def setup_node() -> Tuple[List[Any], List[Any], Optional[str]]:
    """Load network interfaces, start the P2P node, and register a default nickname."""
    allow_windows_firewall("p2pd-demo")

    # Display program banner.
    cout(PROGRAM_BANNER)
    cout("pid = " + str(os.getpid()))

    # Load interfaces on machine.
    cout("Loading networking interfaces...")
    if_names = await list_interfaces()
    if args.nic:
        # --nic narrows to specific interface name(s). Names must match
        # what list_interfaces returns (e.g. on Windows: the description
        # like "Intel(R) 82574L Gigabit Network Connection"; on Linux:
        # the kernel name like "ens192"). Pre-filter here so only the
        # selected NIC(s) get loaded -- otherwise the demo wastes time
        # running STUN / NAT detection on every adapter (mobile NICs,
        # virtual adapters, etc.) and ends up publishing addresses for
        # interfaces the caller never wanted.
        if_names = [n for n in if_names if n in args.nic]
        if not if_names:
            raise ValueError(
                "--nic supplied but no matching interface found. "
                "Requested: {0}; available: {1}".format(
                    args.nic, await list_interfaces(),
                )
            )

    ifs = []
    for attempt in range(3):
        ifs = await load_interfaces(
            if_names, Interface, min_agree=1, max_agree=4, timeout=4
        )
        if ifs:
            break
        if attempt < 2:
            cout("No interfaces found (attempt {0}/3); retrying in 5 s...".format(attempt + 1))
            await asyncio.sleep(5)
    else:
        raise ValueError("Failed to load interfaces.")

    # Show the ifs loaded.
    display_ifs_loaded(ifs)

    # Build the Gate: explicit name when --node_id is supplied,
    # otherwise auto-derive a deterministic sha256(nics+port) name.
    sys_clock_arg = None
    if args.ntp:
        sys_clock_arg = SysClock(interface=ifs[0], ntp_addr=args.ntp)
        cout(fstr("Using --ntp source: {0}", (args.ntp,)))

    gate = None
    for start_attempt in range(3):
        gate = Gate(
            name=args.node_id,
            ifs=ifs, ip=args.ip, port=args.port, stop_rw=stop_rw,
            conf=demo_node_conf, sys_clock=sys_clock_arg,
        )
        # Install the echo protocol handler before start so inbound
        # messages from peers connecting to us get processed.
        gate.add_msg_cb(add_echo_support)
        cout(fstr("Starting node on {0}...", (gate.node.listen_port,)))
        try:
            await gate.__aenter__()
            break
        except StartNodeNicknameFailed:
            await async_wrap_errors(gate.__aexit__(None, None, None))
            if start_attempt < 2:
                cout("PNP servers unreachable (attempt {0}/3); retrying in 5 s...".format(start_attempt + 1))
                await asyncio.sleep(5)
    else:
        # All 3 attempts exhausted. Most likely cause: namebump server
        # was killed. Check 'ps aux | grep namebump' on the PNP host.
        raise StartNodeNicknameFailed()

    node = gate.node

    cout()
    cout(fstr("Node started = {0}", (to_s(node.addr_bytes),)))
    cout(fstr("Node port = {0}", (node.listen_port,)))

    nick = gate.full_name
    if nick is not None:
        cout(fstr("Node nickname = {0}", (nick,)))
        cout()
    else:
        err = gate.nickname_error
        if isinstance(err, PnpServerResourceLimit):
            cout("PNP nickname registration rejected: ResourceLimit.")
            cout("The PNP server's per-source-IP name quota is exhausted.")
            cout("Old names will expire over time; bump the server-side")
            cout("V4_NAME_LIMIT / V6_NAME_LIMIT or wait for pruning.")
        elif isinstance(err, PnpServerUnreachable):
            cout("PNP servers unreachable -- registration could not be verified.")
            cout("Strict registration requires every configured server to respond.")
        elif isinstance(err, FullNameFailure):
            cout("PNP nickname registration failed: " + str(err))
        else:
            cout("node id default nickname didnt load")
            cout("might have been taken over or all servers down.")
        cout("")

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
