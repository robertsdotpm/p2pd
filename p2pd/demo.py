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

# Generate a deterministic address for the node id
# for convienence. display it alongside the nodes addr.
async def main():

    print("Loading networking interfaces...")
    if_names = await list_interfaces()
    ifs = await load_interfaces(if_names)
    buf = "\tifs = "
    for nic in ifs:
        buf += f"{nic.name} "
        for af in nic.supported():
            if af == IP4:
                buf += "(v4)"
            if af == IP6:
                buf += "(v6)"
        buf += "; "
    print(buf)
    print("Starting node...")
    node = P2PNode(ifs=ifs)
    node.add_msg_cb(add_echo_support)
    await node.start(out=True)
    print()
    print(f"Node started = {to_s(node.addr_bytes)}")
    print(f"Node port = {node.listen_port}")
    

    nick = await node.nickname(node.node_id)
    print(f"Node nickname = {nick}")
    print()

    print(\
"""(0) Connect to a node using its nickname or address.
(1) Connect to yourself for testing.
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
            addr = nick
            choice = "0"

        if choice == "0":
            if addr is None:
                addr = input("Enter nodes nickname or address: ")
            print("Connection in progress... Please wait...")

            pipe = await node.connect(addr)
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