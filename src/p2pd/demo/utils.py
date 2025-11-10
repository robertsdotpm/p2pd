import asyncio
from ..do_imports import *
from .cmd_arg_defs import *

def cancel_all_tasks():
    loop = asyncio.get_event_loop()

    # Pre-3.7 compatibility
    if hasattr(asyncio, "all_tasks"):
        tasks = [t for t in asyncio.all_tasks(loop) if not t.done()]
    else:
        tasks = [t for t in asyncio.Task.all_tasks(loop) if not t.done()]

    for t in tasks:
        t.cancel()

    if tasks:
        return asyncio.gather(*tasks, return_exceptions=True)

async def ainput(prompt):
    try:
        import aioconsole
        return await aioconsole.ainput(prompt)
    except ImportError:
        return input(prompt)

def cout(*fargs):
    if args.cmd:
        return
    else:
        if not len(fargs):
            print(flush=True)
        else:
            print(*fargs, flush=True)

async def add_echo_support(msg, client_tup, pipe):
    if b"ECHO" == msg[:4]:
        cout()
        cout("\tGot echo proto msg: " + to_s(msg) + fstr(" from {0}", (client_tup,)))
        cout()
        await pipe.send(msg[4:], client_tup)

        if b"CLEAN_SHUTDOWN" in msg:
            loop = asyncio.get_event_loop()
            asyncio.ensure_future(cancel_all_tasks(), loop=loop)

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
    if ";" in arg_list:
        serv_infos = arg_list.split(";")
    else:
        serv_infos = [arg_list]


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
    if ";" in arg_list:
        serv_infos = arg_list.split(";")
    else:
        serv_infos = [arg_list]

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

def filter_nics_by_mac(mac_str, ifs):
    if "," in mac_str:
        mac_list = mac_str.split(",")
    else:
        mac_list = [mac_str]

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

async def get_dest_addr(last_addr):
    """
    Dest addr may have already been set from previous invocations of the program.
    It's designed to be interactive so you don't have to keep pasting the
    same address for a dest if you're trying to test a remote machine.
    """
    extra_txt = ""
    if last_addr:
        extra_txt = fstr("(enter for {0})", (last_addr["addr"],))

    dest_addr = await ainput(fstr("Enter nodes nickname or address {0}: ", (extra_txt,)))
    if dest_addr == "":
        dest_addr = last_addr["addr"]
    else:
        last_addr["addr"] = dest_addr

    return dest_addr

async def choose_connection_methods(con_method):
    """
    Select a connection method segment.
    """
    cout()
    cout("Connection methods (in order):")
    cout("TCP: (d)irect, (r)everse, (p)unch; UDP: (t)urn.")
    cout("Type menu to return.")
    strats = []
    while True:
        # If pressing enter then use the default list of methods in order.
        con_method = con_method or (await ainput("Enter for default (drp): "))
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

        if strats:
            break
    return strats

async def choose_pathways(pathway):
    """
    Choose the routing pathway to try (this controls IP selection!)
    This is why having accurate interface info is so important.
    """
    cout()
    cout("Enabled connection pathways (in order):")
    cout("WAN: (e)xternal, LAN: (l)ocal ")
    cout("Type menu to return.")
    addr_types = []
    while True:
        pathway = pathway or (await ainput("Enter for default (el): "))
        if not len(pathway):
            addr_types = [EXT_BIND, NIC_BIND]
            break

        if pathway.lower().strip() == "menu":
            return "menu"

        addr_types = []
        for c in pathway:
            c = c.lower()
            if c == 'e':
                addr_types.append(EXT_BIND)
            if c == 'l':
                addr_types.append(NIC_BIND)

        if addr_types:
            break
    return addr_types

async def choose_address_families(addr_type):
    """
    Allows the code to specifically use one or more address families.
    Applicable / useful for dual-stack environments.
    """
    cout()
    cout("Address family priority (in order):")
    cout("(4) IPv4, (6) IPv6")
    cout("Type menu to return.")
    af_priority = []
    while True:
        addr_type = addr_type or (await ainput("Enter for default (46): "))
        if not len(addr_type):
            af_priority = [IP4, IP6]
            break

        if addr_type.lower().strip() == "menu":
            return "menu"

        af_priority = []
        for c in addr_type:
            c = c.lower()
            if c == '4':
                af_priority.append(IP4)
            if c == '6':
                af_priority.append(IP6)

        if af_priority:
            break
    return af_priority

async def echo_client(pipe, echo_data):
    """
    Tunnel is open -- interactive echo client can be used.
    """
    cout("Connection open.")
    cout(pipe.sock)
    cout()
    cout("Basic echo protocol.")
    cout("Enter menu to return to menu or exit to quit.")
    while True:
        send_buf = echo_data or to_b(await ainput("Echo: "))
        if send_buf in (b"quit", b"exit"):
            return "exit"
        if send_buf in (b"menu"):
            send_buf = b""
            return "menu"
        await pipe.send(b"ECHO " + send_buf + b"\n")
        buf = await pipe.recv(timeout=3)
        cout(b"recv = ", buf, b"\n")
        if echo_data:
            print(buf + b"\n", flush=True)
            return "exit"