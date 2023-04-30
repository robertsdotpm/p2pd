from p2pd import *

class NetInfoServer(Daemon):
    async def msg_cb(self, msg, client_tup, pipe):
        # Parse HTTP message and handle CORS.
        req = await rest_service(msg, client_tup, pipe)
        #
        async def get_response():
            # Show information of the connection to the peer.
            p = req.api("/mapping")
            if p:
                sock = pipe.sock
                return {
                    "error": 0,
                    "fd": sock.fileno(),
                    "laddr": sock.getsockname(),
                    "raddr": sock.getpeername(),
                    "route": pipe.route.to_dict(),
                    "if": {
                        "name": pipe.route.interface.name
                    }
                }
            #
            # Fallback and serve all other purposes.
            return {
                "error": 2,
                "msg": "method not implemented"
            }
        #
        resp = await get_response()
        if resp is not None:
            await send_json(
                resp,
                req,
                client_tup,
                pipe
            )

async def example():
    netifaces = await init_p2pd()
    #
    # Default interface of your machine.
    # netifaces.interfaces() for names
    # or await load_interfaces() for a started list.
    i = await Interface(netifaces=netifaces).start()
    #
    # Server object inherits from a standard Daemon.
    server = NetInfoServer()
    #
    # Makes a Route aware of all Routes used for the server.
    # Might do this automatically in the future.
    server.set_rp(i.rp)
    #
    # Defines addresses and protocols to listen on.
    # Feel free to switch this up.
    await server.listen_all(
        # Listen on all routes for IP4 and IPv6.
        [i.rp[IP4], i.rp[IP6]],
        #
        # Port(s) to listen on.
        [20000],
        #
        # Interested in TCP and UDP.
        [TCP, UDP]
    )
    # Do a while sleep loop ...
    # Instead we'll just close.
    await server.close()

if __name__ == '__main__':
    async_test(example)