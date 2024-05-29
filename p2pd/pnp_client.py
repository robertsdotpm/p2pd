from .base_stream import *
from .pnp_utils import *

"""
Important: since this immediately returns if one
were to follow-up with another call without waiting for
status receipt it may return an invalid value
indicating that the server hasn't done the previous call yet.
"""
class PNPClient():
    def __init__(self, sk, dest, proto=TCP):
        self.dest = dest
        self.sk = sk
        self.vkc = sk.verifying_key.to_string("compressed")
        self.names = {}
        self.proto = proto

    async def get_dest_pipe(self):
        route = self.dest.route.interface.route(self.dest.route.af)
        route = await route.bind()
        pipe = await pipe_open(self.proto, route, self.dest)
        return pipe

    async def return_resp(self, pipe):
        try:
            buf = await proto_recv(pipe)
            pkt = PNPPacket.unpack(buf)
            if not pkt.updated:
                pkt.value = None

            return pkt
        except:
            log_exception()
            return None
        finally:
            await pipe.close()

    async def push(self, name, value, behavior=BEHAVIOR_DO_BUMP):
        pipe = await self.get_dest_pipe()
        pkt = PNPPacket(name, value, self.vkc, behavior=behavior)
        pnp_msg = pkt.get_msg_to_sign()
        sig = self.sk.sign(pnp_msg)
        print("Sending sig = ")
        print(sig)
        print("sending pre msg = ")
        print(pnp_msg)
        await pipe.send(pnp_msg + sig)
        return await self.return_resp(pipe)

    async def fetch(self, name):
        pipe = await self.get_dest_pipe()
        pkt = PNPPacket(name, vkc=self.vkc)
        pnp_msg = pkt.get_msg_to_sign()
        await pipe.send(pnp_msg)
        return await self.return_resp(pipe)

    async def delete(self, name):
        pipe = await self.get_dest_pipe()
        pkt = PNPPacket(name, vkc=self.vkc)
        pnp_msg = pkt.get_msg_to_sign()
        sig = self.sk.sign(pnp_msg)
        print("Sending sig = ")
        print(sig)
        print("sending pre msg = ")
        print(pnp_msg)
        await pipe.send(pnp_msg + sig)
        return await self.return_resp(pipe)