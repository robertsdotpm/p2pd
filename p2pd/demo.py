import asyncio
from .do_imports import *

IS_DEBUG = 2

def patch_log_p2p(m, node_id=""):
    out = f"p2p: <{node_id}> {m}"
    print(out)

Log.log_p2p = patch_log_p2p

async def add_echo_support(msg, client_tup, pipe):
    if b"ECHO" == msg[:4]:
        print()
        print(f"\tGot echo proto msg: {msg} from {client_tup}")
        print()
        await pipe.send(msg[4:], client_tup)

nat_txt = {
    OPEN_INTERNET: "open internet",
    SYMMETRIC_UDP_FIREWALL: "udp firewall",
    FULL_CONE: "full cone",
    RESTRICT_NAT: "restrict",
    RESTRICT_PORT_NAT: "restrict port",
    SYMMETRIC_NAT: "symmetric",
    BLOCKED_NAT: "blocked"
}

delta_txt = {
    NA_DELTA: "not applicable",
    EQUAL_DELTA: "equal",
    PRESERV_DELTA: "preserving",
    INDEPENDENT_DELTA: "independent",
    DEPENDENT_DELTA: "dependent",
    RANDOM_DELTA: "random"
}

method_txt = {
    "d": P2P_DIRECT,
    "r": P2P_REVERSE,
    "p": P2P_PUNCH,
    "t": P2P_RELAY,
}

async def main():
    print("Universal reachability demo")
    print("Coded by matthew@roberts.pm")
    print("-----------------------------")
    print()
    print("Loading networking interfaces...")
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)
    buf = ""
    for nic in ifs:
        buf += f"\t{nic.name} "
        for af in nic.supported():
            if af == IP4:
                buf += "(v4)"
            if af == IP6:
                buf += "(v6)"
        buf += f"\n\t\t{nat_txt[nic.nat['type']]} nat; "
        buf += f"{delta_txt[nic.nat['delta']['type']]} delta = "
        buf += f"{nic.nat['delta']['value']}"
        buf += "\n"
    print(buf[:-1])
    print("Starting node...")

    nodes = []
    node = P2PNode(ifs=ifs)
    node.add_msg_cb(add_echo_support)
    await node.start(out=True)
    nodes.append(node)
    print()
    print(f"Node started = {to_s(node.addr_bytes)}")
    print(f"Node port = {node.listen_port}")
    
    try:
        nick = await node.nickname(node.node_id)
        print(f"Node nickname = {nick}")
        print()
    except:
        log_exception()
        print("node id default nickname didnt load")
        print("might have been taken over or all servers down.")

    print(\
"""(0) Connect to a node using its nickname or address.
(1) Start accepting connections (this stops the input loop)
(2) Start additional node for testing (needed for self punch.)
(3) Register a unique nickname for your node.
(4) Exit program.
""")

    last_addr = ""
    choice = None
    while 1:
        choice = input("Select menu option: ")
        if choice not in ("0", "1", "2", "3", "exit", "quit"):
            continue

        if choice in ("exit", "quit"):
            choice = "4"

        if choice == "1":
            while 1:
                await asyncio.sleep(1)

        if choice == "3":
            choice = input("Enter nickname: ")
            try:
                ret = await node.nickname(choice)
                print(f"Nickname registered = {ret}")
            except:
                print("Nickname taken.")

            continue

        addr = None
        if choice == "2":
            alice = nodes[-1]
            bob = P2PNode(port=alice.listen_port + 1, ifs=ifs)
            bob.add_msg_cb(add_echo_support)
            bob.stun_clients = alice.stun_clients
            await bob.start(sys_clock=alice.sys_clock, out=True)
            print()
            print(f"New node addr = {to_s(bob.addr_bytes)}")
            ret = await bob.nickname(bob.node_id)
            print(f"New node port = {bob.listen_port}")
            print(f"New node nickname = {ret}")
            nodes.append(bob)
            print()
            continue

        if choice == "0":
            if addr is None:
                prefix = ""
                if len(last_addr):
                    prefix = f" (enter for {last_addr})"

                addr = input(f"Enter nodes nickname or address{prefix}: ")
                if addr == "":
                    addr = last_addr
                else:
                    last_addr = addr
            

            print()
            print("Connection methods (in order):")
            print("TCP: (d)irect, (r)everse, (p)unch; UDP: (t)urn")
            strats = []
            while 1:
                methods = input("Enter for default (drp): ")
                if not len(methods):
                    strats = P2P_STRATEGIES
                    break

                strats = []
                for c in methods:
                    c = c.lower()
                    if c in method_txt:
                        strats.append(method_txt[c])

                if not len(strats):
                    continue
                else:
                    break

            print(strats)

            print()
            print("Enabled connection pathways (in order):")
            print("WAN: (e)xternal, LAN: (l)ocal ")
            addr_types = []
            while 1:
                pathway = input("Enter for default (el): ")
                if not len(pathway):
                    addr_types = [EXT_BIND, NIC_BIND]
                    break

                addr_types = []
                for c in pathway:
                    c  = c.lower()
                    if c == 'e':
                        addr_types.append(EXT_BIND)
                    if c == 'l':
                        addr_types.append(NIC_BIND)


                if not len(addr_types):
                    continue
                else:
                    break

            print()
            print("Address family priority (in order):")
            print("(4) IPv4, (6) IPv6")
            af_priority = []
            while 1:
                afs = input("Enter for default (46): ")
                if not len(afs):
                    af_priority = [IP4, IP6]
                    break

                af_priority = []
                for c in afs:
                    c  = c.lower()
                    if c == '4':
                        af_priority.append(IP4)
                    if c == '6':
                        af_priority.append(IP6)

                if not len(af_priority):
                    continue
                else:
                    break

            print()
            print("Connection in progress... Please wait...")
            pipe_conf = {
                "addr_types": addr_types,
                "addr_families": af_priority,
                "return_msg": False,
            }

            pipe = await node.connect(addr, strategies=strats, conf=pipe_conf)
            if pipe is None:
                print("Connection failed.")
                continue
            else:
                print("Connection open.")
                print(pipe.sock)
                print()
                print("Basic echo protocol.")
                print("Enter menu to return to menu or exit to quit.")
                while 1:
                    choice = to_b(input("Echo: "))
                    if choice in (b"quit", b"exit"):
                        choice = "4"
                        break
                    if choice in (b"menu"):
                        choice = ""
                        await pipe.close()
                        break

                    await pipe.send(b"ECHO " + choice + b"\n")
                    buf = await pipe.recv(timeout=3)
                    print(f"recv = {buf}")

        if choice == "4":
            print("Stopping nodes...")
            print("May take a while... work in progress")
            print("(I usually just spam cnt + c)")
            for n in nodes:
                await n.close()
            return



if __name__ == "__main__":
    async_test(main)