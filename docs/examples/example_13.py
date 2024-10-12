from p2pd import *

class NetInfoServer(Daemon):
    async def msg_cb(self, msg, client_tup, pipe):
        # Parse HTTP message and handle CORS.
        req = await rest_service(msg, client_tup, pipe)

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
        
        resp = await get_response()
        if resp is not None:
            await send_json(
                resp,
                req,
                client_tup,
                pipe
            )

async def example():
    # Default interface of your machine.
    # netifaces.interfaces() for names or
    # if_names = await list_interfaces()
    # await load_interfaces(if_names) for a started list.
    nic = await Interface()
    
    # Server object inherits from a standard Daemon.
    server = NetInfoServer()
    
    # Defines addresses and protocols to listen on.
    # Feel free to switch this up.
    await server.listen_all(TCP, 20000, nic)
    await server.listen_all(UDP, 20000, nic)
    
    # Do a while sleep loop ...
    # Instead we'll just close.
    await server.close()

if __name__ == '__main__':
    async_test(example)