import asyncio
import os
import select
import sys
from ..do_imports import *
from .cmd_arg_defs import *

# Pipe used to unblock ainput() when the program shuts down.
# Writing any byte to ainput_interrupt_w causes all pending ainput() calls to return "".
ainput_interrupt_r, ainput_interrupt_w = os.pipe()

async def ainput(prompt):
    loop = asyncio.get_event_loop()

    def _blocking_input():
        sys.stdout.write(prompt)
        sys.stdout.flush()
        try:
            r, _, _ = select.select([sys.stdin.fileno(), ainput_interrupt_r], [], [])
        except Exception:
            return ""
        if sys.stdin.fileno() not in r:
            return ""  # Interrupted by shutdown signal
        try:
            line = sys.stdin.readline()
            return line.rstrip('\n') if line else ""
        except Exception:
            return ""

    fut = loop.run_in_executor(None, _blocking_input)
    try:
        return await fut
    except asyncio.CancelledError:
        # Unblock the _blocking_input thread so the executor shuts down cleanly.
        try:
            os.write(ainput_interrupt_w, b'\x01')
        except OSError:
            pass
        raise

def cout(*fargs):
    if args.cmd:
        return
    else:
        if not len(fargs):
            print(flush=True)
        else:
            print(*fargs, flush=True)

async def add_echo_support(msg, client_tup, pipe):
    print("in add echo sup ", msg)
    if b"ECHO" == msg[:4]:
        cout()
        cout("\tGot echo proto msg: " + to_s(msg) + fstr(" from {0}", (client_tup,)))
        cout()
        await pipe.send(msg[4:], client_tup)

        # Maybe give event loop chance to send before exit, IDK.

        if b"CLEAN_SHUTDOWN" in msg:
            log("reached clean shutdown in add echo")
            # Try give event loop time to send.
            # Since this will shut down -- got to be a better way to ensure send
            # has finished before closing TODO
            for _ in range(0, 5):
                await asyncio.sleep(0.1)


            stop_rw[1].send(b"Clean shutdown.")

            return

def patch_log_p2p(m, node_id=""):
    out = fstr("p2p: <{0}> ", (node_id,)) + to_s(m)
    cout(out)

def get_req_serv_parts(parts):
    ip = parts[2]
    offset = int(parts[0])
    af = int(parts[1])
    port = int(parts[3])
    if af == 4:
        af = IP4
    else:
        af = IP6

    return offset, af, ip, port

def patch_server_af_dict(arg_list, serv_dict):
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

def patch_server_list(arg_list, server_list):
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
                "afs": []
            }
        else:
            entry = server_list[offset]

        entry[af] = ip
        entry["afs"].append(af)
        server_list[offset] = entry

def filter_nics_by_mac(mac_list, ifs):
    mac_list = [mac_norm(mac) for mac in mac_list]
    new_ifs = []
    for nic in ifs:
        if nic.mac in mac_list:
            new_ifs.append(nic)

    return new_ifs

def display_ifs_loaded(ifs):
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
    cout(buf)

async def get_dest_addr(node, last_addr):
    """
    Dest addr may have already been set from previous invocations of the program.
    It's designed to be interactive so you don't have to keep pasting the
    same address for a dest if you're trying to test a remote machine.

    If the entered value is a TLD nickname, resolution via MQTT is attempted
    immediately.  On failure the user is prompted to paste a full serialized
    address instead.
    """
    extra_txt = ""
    if last_addr:
        extra_txt = fstr("(enter for {0})", (last_addr["addr"],))

    dest_addr = await ainput(fstr("Enter nodes nickname or address {0}: ", (extra_txt,)))
    if dest_addr.lower().strip() == "menu":
        return "menu"
    if dest_addr == "":
        dest_addr = last_addr["addr"]
    else:
        last_addr["addr"] = dest_addr

    if pnp_name_has_tld(dest_addr):
        cout(fstr("Resolving {0}...", (dest_addr,)))
        try:
            addr_bytes, _ = await resolve_pnp_addr(node, dest_addr)
            return addr_bytes
        except Exception as e:
            cout(fstr("Nickname lookup failed ({0}).", (e,)))
            cout("Please paste the full serialized node address instead.")
            fallback = await ainput("Address: ")
            if fallback.lower().strip() == "menu":
                return "menu"
            last_addr["addr"] = fallback
            return fallback

    return dest_addr

async def choose_connection_methods(con_method):
    """
    Select a connection method segment.
    """
    cout()
    cout("Connection methods (in order):")
    cout("TCP: (d)irect, (r)everse, (p)unch; UDP: (t)urn.")
    cout("Type menu to return.")
    while True:
        # If pressing enter then use the default list of methods in order.
        con_method = con_method or (await ainput("Enter for default (d): "))
        if not len(con_method):
            return "direct_connect"

        # Go back to the menu.
        con_method = con_method.lower().strip()
        if con_method == "menu":
            return "menu"
        
        if con_method not in method_txt:
            con_method = None
            continue

        return method_txt[con_method]

async def choose_pathways(pathway):
    """
    Choose the routing pathway to try (this controls IP selection!)
    This is why having accurate interface info is so important.
    """
    cout()
    cout("Choose connection pathway:")
    cout("WAN: (e)xternal, LAN: (l)ocal")
    cout("Type menu to return.")
    while not sock_has_data(stop_rw[0]):
        pathway = pathway or (await ainput("Enter for default (e): "))
        if not len(pathway):
            return EXT_BIND

        if pathway.lower().strip() == "menu":
            return "menu"

        for c in pathway:
            c = c.lower()
            if c == 'e':
                return EXT_BIND
            if c == 'l':
                return NIC_BIND
        pathway = None

async def choose_address_families(addr_type):
    """
    Allows the code to specifically use one or more address families.
    Applicable / useful for dual-stack environments.
    """
    cout()
    cout("Address family priority:")
    cout("(4) IPv4, (6) IPv6")
    cout("Type menu to return.")
    while not sock_has_data(stop_rw[0]):
        addr_type = addr_type or (await ainput("Enter for default (4): "))
        if not len(addr_type):
            return IP4

        if addr_type.lower().strip() == "menu":
            return "menu"

        for c in addr_type:
            c = c.lower()
            if c == '4':
                return IP4
            if c == '6':
                return IP6
        addr_type = None

async def echo_client(pipe, echo_data):
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
        
        await pipe.send(b"ECHO " + send_buf + b"\n")
        buf = await pipe.recv(timeout=4)
        cout(b"recv = ", buf, b"\n")
        if echo_data:
            print(buf + b"\n", flush=True)
            return "exit"