from ..do_imports import *
from .cmd_arg_defs import *

def cout(*fargs):
    if args.cmd:
        return
    else:
        if not len(fargs):
            print()
        else:
            print(*fargs)

async def add_echo_support(msg, client_tup, pipe):
    if b"ECHO" == msg[:4]:
        cout()
        cout("\tGot echo proto msg: " + to_s(msg) + fstr(" from {0}", (client_tup,)))
        cout()
        await pipe.send(msg[4:], client_tup)

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