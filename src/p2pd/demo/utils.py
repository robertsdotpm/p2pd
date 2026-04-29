"""Helper utilities for the p2pd demo application."""
import asyncio
import os
import platform
import select
import sys
from aionetiface import (
    Any, Dict, EXT_BIND, IP4, IP6, List, NIC_BIND, Optional,
    fstr, log, mac_norm, sock_has_data, to_b, to_s,
)
from ..node.nickname import pnp_name_has_tld
from ..node.node_connect import resolve_pnp_addr
from . import stop_rw
from .cmd_arg_defs import args
from .defs import delta_txt, method_txt, nat_txt

# Pipe used to unblock ainput() when the program shuts down.
# Writing any byte to ainput_interrupt_w causes all pending ainput() calls
# to return "". POSIX-only -- on Windows we rely on the readline() blocking
# call returning naturally on Ctrl+C / EOF since select.select() can't watch
# stdin or pipe fds there.
ainput_interrupt_r = ainput_interrupt_w = -1
_IS_WINDOWS = platform.system() == "Windows"
if not _IS_WINDOWS:
    ainput_interrupt_r, ainput_interrupt_w = os.pipe()


async def ainput(prompt: str) -> str:
    """Read a line of input from stdin asynchronously, unblocking on shutdown signals."""
    loop = asyncio.get_event_loop()

    def blocking_input() -> str:
        """Block in a thread waiting for stdin input or a shutdown interrupt.

        On POSIX we use select() over stdin + a shutdown-interrupt
        pipe so a Ctrl+C / signal can release the read. On Windows
        select() only accepts socket fds (raises OSError on a stdin
        or pipe fd) -- previously this fired on every iteration,
        returned "" immediately, and the menu loop spun without ever
        blocking. Plain readline() works there; the trade-off is the
        Ctrl+C handling is whatever the runtime gives us by default.
        """
        sys.stdout.write(prompt)
        sys.stdout.flush()
        if _IS_WINDOWS:
            try:
                line = sys.stdin.readline()
            except (OSError, IOError):
                return ""
            return line.rstrip("\n").rstrip("\r") if line else ""

        try:
            r, _, _ = select.select([sys.stdin.fileno(), ainput_interrupt_r], [], [])
        except (OSError, IOError):
            return ""
        if sys.stdin.fileno() not in r:
            return ""  # Interrupted by shutdown signal
        try:
            line = sys.stdin.readline()
            return line.rstrip("\n") if line else ""
        except (OSError, IOError):
            return ""

    fut = loop.run_in_executor(None, blocking_input)
    try:
        return await fut
    except asyncio.CancelledError:
        # Unblock the blocking_input thread so the executor shuts down
        # cleanly.
        if not _IS_WINDOWS and ainput_interrupt_w >= 0:
            try:
                os.write(ainput_interrupt_w, b"\x01")
            except OSError:
                pass
        raise


def cout(*fargs) -> None:
    """Print output to stdout unless running in non-interactive command mode."""
    if args.cmd:
        return
    if not fargs:
        print(flush=True)
    else:
        print(*fargs, flush=True)


async def add_echo_support(msg: bytes, client_tup: Any, pipe: Any) -> None:
    """Handle incoming ECHO protocol messages by stripping the prefix and sending back the payload."""
    print("[ECHO-CB] msg={0!r} client_tup={1!r}".format(msg[:48], client_tup))
    if b"ECHO" == msg[:4]:
        cout()
        cout("\tGot echo proto msg: " + to_s(msg) + fstr(" from {0}", (client_tup,)))
        cout()
        await pipe.send(msg[4:], client_tup)
        print("[ECHO-CB] replied to {0}".format(client_tup))

        # Maybe give event loop chance to send before exit, IDK.

        if b"CLEAN_SHUTDOWN" in msg:
            log("reached clean shutdown in add echo")
            # Try give event loop time to send.
            # Since this will shut down -- got to be a better way to ensure
            # send has finished before closing TODO
            for _ in range(0, 5):
                await asyncio.sleep(0.1)

            stop_rw[1].send(b"Clean shutdown.")

            return


def patch_log_p2p(m: Any, node_id: str = "") -> None:
    """Format and print a P2P log line prefixed with the node ID via cout."""
    out = fstr("p2p: <{0}> ", (node_id,)) + to_s(m)
    cout(out)


def get_req_serv_parts(parts: List[str]) -> Any:
    """Parse a comma-separated server spec into (offset, af, ip, port) tuple."""
    ip = parts[2]
    offset = int(parts[0])
    af = int(parts[1])
    port = int(parts[3])
    if af == 4:
        af = IP4
    else:
        af = IP6

    return offset, af, ip, port


def patch_server_af_dict(arg_list: List[str], serv_dict: Dict[Any, Any]) -> None:
    """Override host/ip/port entries in an AF-keyed server dict using CLI arg strings."""
    # offset, af, ip, port
    serv_infos = arg_list
    for serv_info in serv_infos:
        parts = serv_info.split(",")
        offset, af, ip, port = get_req_serv_parts(parts)
        serv_dict[af][offset]["host"] = ip
        serv_dict[af][offset]["ip"] = ip
        serv_dict[af][offset]["port"] = port
        if "afs" not in serv_dict:
            serv_dict["afs"] = []


def patch_server_list(arg_list: List[str], server_list: List[Dict[str, Any]]) -> None:
    """Patch entries in a flat server list with addresses and credentials from CLI arg strings."""
    # offset, af, ip, port, (optional) user, (optional) password
    serv_infos = arg_list
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
                "afs": [],
            }
        else:
            entry = server_list[offset]

        entry[af] = ip
        entry["afs"].append(af)
        server_list[offset] = entry


def filter_nics_by_mac(mac_list: List[str], ifs: List[Any]) -> List[Any]:
    """Return only the NICs whose MAC address appears in mac_list."""
    mac_list = [mac_norm(mac) for mac in mac_list]
    new_ifs = []
    for nic in ifs:
        if nic.mac in mac_list:
            new_ifs.append(nic)

    return new_ifs


def display_ifs_loaded(ifs: List[Any]) -> None:
    """Print a summary of each loaded interface including AF support and NAT type."""
    buf = ""
    for nic in ifs:
        buf += fstr("\t{0} ", (nic.name,))
        for af in nic.supported():
            if af == IP4:
                buf += "(v4)"
            if af == IP6:
                buf += "(v6)"
        buf += fstr("\n\t\t{0} nat; ", (nat_txt[nic.nat["type"]],))
        buf += fstr("{0} delta = ", (delta_txt[nic.nat["delta"]["type"]],))
        buf += fstr("{0}", (nic.nat["delta"]["value"],))
        buf += "\n"
    cout(buf)


async def get_dest_addr(node: Any, last_addr: Any) -> Any:
    """
    Dest addr may have already been set from previous invocations of the
    program.
    It's designed to be interactive so you don't have to keep pasting the
    same address for a dest if you're trying to test a remote machine.

    If the entered value is a TLD nickname, resolution via MQTT is attempted
    immediately.  On failure the user is prompted to paste a full serialized
    address instead.
    """
    extra_txt = ""
    if last_addr:
        extra_txt = fstr("(enter for {0})", (last_addr["addr"],))

    dest_addr = await ainput(
        fstr("Enter nodes nickname or address {0}: ", (extra_txt,))
    )
    if dest_addr.lower().strip() == "menu":
        return "menu"
    if dest_addr == "":
        dest_addr = last_addr["addr"]
    else:
        last_addr["addr"] = dest_addr

    if pnp_name_has_tld(dest_addr):
        cout(fstr("Resolving {0}...", (dest_addr,)))
        try:
            addr_bytes, _, source = await resolve_pnp_addr(node, dest_addr)
            cout(
                fstr(
                    "Resolved via {0}: {1}",
                    (
                        source,
                        addr_bytes,
                    ),
                )
            )
            return addr_bytes
        except (
            OSError,
            ConnectionError,
            asyncio.TimeoutError,
            ValueError,
        ) as e:
            cout(fstr("Nickname lookup failed ({0}).", (e,)))
            cout("Please paste the full serialized node address instead.")
            fallback = await ainput("Address: ")
            if fallback.lower().strip() == "menu":
                return "menu"
            last_addr["addr"] = fallback
            return fallback

    return dest_addr


async def choose_connection_methods(con_method: Optional[str]) -> str:
    """
    Select a connection method segment.
    """
    cout()
    cout("Connection methods:")
    cout("  0) direct        (TCP)")
    cout("  1) reverse       (TCP)")
    cout("  2) tcp_punch     (TCP, predictable NAT)")
    cout("  3) turn relay    (UDP)")
    cout("  4) random probe  (UDP, symmetric NAT)")
    cout("  5) auto          (try each in order)")
    cout("  6) udp_punch     (UDP, predictable NAT)")
    cout("Type menu to return.")
    while True:
        # If pressing enter then use the default first method.
        con_method = con_method or (await ainput("Enter for default (0): "))
        if not con_method:
            return "direct_connect"

        # Go back to the menu.
        con_method = con_method.lower().strip()
        if con_method == "menu":
            return "menu"

        if con_method not in method_txt:
            con_method = None
            continue

        return method_txt[con_method]


async def choose_pathways(pathway: Optional[str]) -> Any:
    """
    Choose the routing pathway to try (this controls IP selection!)
    This is why having accurate interface info is so important.

    The (a)ny option returns None, which downstream is interpreted as
    "leave the route_type unconstrained" -- for plugins like
    reverse_connect, that means the responder is free to pick any
    route_type at its end.
    """
    cout()
    cout("Choose connection pathway:")
    cout("WAN: (e)xternal, LAN: (l)ocal, (a)ny")
    cout("Type menu to return.")
    while not sock_has_data(stop_rw[0]):
        pathway = pathway or (await ainput("Enter for default (e): "))
        if not pathway:
            return EXT_BIND

        if pathway.lower().strip() == "menu":
            return "menu"

        for c in pathway:
            c = c.lower()
            if c == "e":
                return EXT_BIND
            if c == "l":
                return NIC_BIND
            if c == "a":
                return None
        pathway = None


async def choose_address_families(addr_type: Optional[str]) -> Any:
    """
    Allows the code to specifically use one or more address families.
    Applicable / useful for dual-stack environments.

    The (a)ny option returns None, which downstream is interpreted as
    "leave the address family unconstrained" -- for plugins like
    reverse_connect, that means the responder is free to pick whichever
    AF works at its end.
    """
    cout()
    cout("Address family priority:")
    cout("(4) IPv4, (6) IPv6, (a)ny")
    cout("Type menu to return.")
    while not sock_has_data(stop_rw[0]):
        addr_type = addr_type or (await ainput("Enter for default (4): "))
        if not addr_type:
            return IP4

        if addr_type.lower().strip() == "menu":
            return "menu"

        for c in addr_type:
            c = c.lower()
            if c == "4":
                return IP4
            if c == "6":
                return IP6
            if c == "a":
                return None
        addr_type = None


async def echo_client(pipe: Any, echo_data: Optional[bytes]) -> str:
    """
    Tunnel is open -- interactive echo client can be used.
    """
    cout("Connection open.")
    cout(pipe.sock)
    cout()
    cout("Basic echo protocol.")
    cout("Enter menu to return to menu.")
    while not sock_has_data(stop_rw[0]):
        send_buf = echo_data or to_b(await ainput("Echo: "))
        if send_buf in (b"menu"):
            send_buf = b""

            return "menu"

        # Empty input -- just re-prompt. Don't send a bare ECHO frame
        # to the peer; that wastes a round-trip and on slow stacks the
        # 4s recv timeout makes the prompt feel laggy.
        if not send_buf:
            continue

        await pipe.send(b"ECHO " + send_buf + b"\n")
        buf = await pipe.recv(timeout=4)
        cout(b"recv = ", buf, b"\n")
        if echo_data:
            # buf is None when pipe.recv() times out -- e.g. the
            # punched pipe wrapped the wrong socket and the echo
            # reply landed on a different fd. Print a diagnostic
            # marker instead of crashing on None + bytes so the
            # log shows the recv timeout cleanly and the test
            # harness records NO_ECHO rather than a TypeError.
            if buf is None:
                print(b"recv-timeout (None)\n", flush=True)
            else:
                print(buf + b"\n", flush=True)
            return "exit"
