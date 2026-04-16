from p2pd import *

async def msg_cb(msg, client_tup, pipe):
    await pipe.send(msg, client_tup)

async def example():
    # Start the server and use msg_cb to process messages.
    server = await pipe_open(TCP, msg_cb=msg_cb)
    async with server:
        # Connect to the server.
        dest = server.sock.getsockname()[0:2]
        client = await pipe_open(TCP, dest)
        async with client:
            # Send data to the server and check receipt.
            msg = b"test msg."
            await client.send(msg)
            out = await client.recv()
            assert(msg == out)

# From inside the async REPL.
if __name__ == '__main__':
    async_test(example)