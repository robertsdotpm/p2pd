from p2pd import *

async def msg_cb(msg, client_tup, pipe):
    print(f"echoed back got {msg} {client_tup}")
    print(pipe.sock)

async def client_msg_cb(msg, client_tup, pipe):
    print(f"client got {msg} {client_tup}")
    print(pipe.sock)

async def upstream_msg_cb(msg, client_tup, pipe):
    print(f"upstream got {msg} {client_tup}")
    print(pipe.sock)

# set P2PD_DEBUG=1 && cd projects/p2pd/tests && python sim.py
async def workspace():
    nic = await Interface()
    af = IP4

    reverse_route = await nic.route(af).bind()
    reverse_serv = await pipe_open(
        TCP,
        dest=None,
        route=reverse_route,
        msg_cb=msg_cb,
    )

    upstream = await pipe_open(
        TCP,
        ("tcpbin.com", 4242),
        await nic.route(af).bind(),
        msg_cb=upstream_msg_cb
    )

    client = await pipe_open(
        TCP,
        reverse_serv.sock.getsockname()[:2],
        await nic.route(af).bind(),
        msg_cb=client_msg_cb
    )

    upstream.add_pipe(client)
    client.add_pipe(upstream)

    accepted = reverse_serv.tcp_clients[0]
    while 1:
        buf = input("to send")
        buf = to_b(buf) + b"\r\n\r\n"
        await accepted.send(buf)
        print(accepted.sock)

        await asyncio.sleep(1)
        


async_test(workspace)