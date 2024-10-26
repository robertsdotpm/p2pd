import asyncio
from .do_imports import *

IS_DEBUG = 2

def patch_log_p2p(m, node_id=""):
    out = f"p2p: <{node_id}> {m}"
    print(out)

Log.log_p2p = patch_log_p2p

async def add_echo_support(msg, client_tup, pipe):
    if b"ECHO" == msg[:4]:
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

# Generate a deterministic address for the node id
# for convienence. display it alongside the nodes addr.
async def main():

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
    

    nick = await node.nickname(node.node_id)
    print(f"Node nickname = {nick}")
    print()

    print(\
"""(0) Connect to a node using its nickname or address.
(1) Start additional node for testing (for self punch.)
(2) Register a unique nickname for your node.
(3) Exit
""")

    choice = None
    while 1:
        choice = input("Select option: ")
        if choice not in ("0", "1", "2", "3"):
            continue

        if choice == "2":
            choice = input("Enter nickname: ")
            try:
                ret = await node.nickname(choice)
                print(f"Nickname registered = {ret}")
            except:
                print("Nickname taken.")

            continue

        addr = None
        if choice == "1":
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
                addr = input("Enter nodes nickname or address: ")
            

            print()
            print("Connection methods:")
            print("TCP: (d)irect, (r)everse, (p)unch; UDP: (t)urn")
            strats = []
            while 1:
                methods = input("Default (drp): ")
                if not len(methods):
                    methods = P2P_STRATEGIES
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

            print()
            print("Enabled connection pathways:")
            print("WAN: (e)xternal, LAN: (l)ocal ")
            addr_types = []
            while 1:
                pathway = input("Default (el): ")
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
            print("Connection in progress... Please wait...")
            pipe_conf = {
                "addr_types": addr_types,
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
                while 1:
                    choice = to_b(input("Echo: "))
                    await pipe.send(b"ECHO " + choice + b"\n")
                    buf = await pipe.recv(timeout=3)
                    print(f"recv = {buf}")

        if choice == "3":
            print("Stopping node...")
            await node.close()
            return





async_test(main)