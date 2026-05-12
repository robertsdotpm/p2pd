"""
code a function for is_node_reachable_over_mqtt for debugging

I did delete the thing that saves send msg tasks in the mqtt client
idk if thats relevant.

python3 -m warpgate.demo --pnp_server 0,4,<ntp-host>,5300 --cmd 0dl4 \
    --dest_addr 5b5ed965936a5f28c2795724a.p2p --echo "hello world"

python3 -m warpgate.demo --disable_upnp 1 \
    --pnp_server 0,4,<ntp-host>,5300 --ip <local-ip>
python3 -m warpgate.demo --disable_upnp 1 \
    --pnp_server 0,4,<ntp-host>,5300 --ip <local-ip>

python3 -m warpgate.demo --disable_upnp 1 --nic <mac-or-name>
python3 -m warpgate.demo --disable_upnp 1 --nic <mac-or-name>
"""
import asyncio
import time
import signal
import os
from aionetiface import (
    StartNodeNicknameFailed, TunnelFailed,
    allow_windows_firewall,
    async_run, async_wrap_errors, fstr,
    log, log_exception,
    sock_has_data, sys, to_b, to_s,
)
from ..node.nickname import (
    FullNameFailure, PnpServerResourceLimit, PnpServerUnreachable,
)
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


async def setup_node():
    """Load network interfaces, start the P2P node, and register a default nickname."""
    allow_windows_firewall("warpgate-demo")

    # Display program banner.
    cout(PROGRAM_BANNER)
    cout("pid = " + str(os.getpid()))

    cout("Loading networking interfaces...")

    gate = None
    for start_attempt in range(3):
        gate = Gate(
            name=args.node_id,
            nic_names=args.nic or None,
            ntp_addr=args.ntp or None,
            ip=args.ip, port=args.port, stop_rw=stop_rw,
            conf=demo_node_conf,
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
        except asyncio.CancelledError:
            await async_wrap_errors(gate.__aexit__(None, None, None))
            raise
        except Exception:
            await async_wrap_errors(gate.__aexit__(None, None, None))
            raise
    else:
        # All 3 attempts exhausted. Most likely cause: namebump server
        # was killed. Check 'ps aux | grep namebump' on the PNP host.
        raise StartNodeNicknameFailed()

    node = gate.node
    ifs = node.ifs

    # Show which interfaces were loaded and their NAT classification.
    display_ifs_loaded(ifs)

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


async def run_node_loop(nodes, ifs, nick):
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


async def main():
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

        def set_shut_down():
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
