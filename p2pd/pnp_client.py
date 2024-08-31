# TODO: different key per request.

from .ecies import generate_key, decrypt, encrypt
from .pipe_utils import *
from .pnp_utils import *

"""
Important: since this immediately returns if one
were to follow-up with another call without waiting for
status receipt it may return an invalid value
indicating that the server hasn't done the previous call yet.
"""
class PNPClient():
    def __init__(self, sk, dest, dest_pk, proto=TCP):
        self.dest_pk = dest_pk
        assert(isinstance(dest_pk, bytes))
        self.dest = dest
        self.sk = sk
        self.vkc = sk.verifying_key.to_string("compressed")
        self.names = {}
        self.proto = proto
        secp_k = generate_key()
        self.reply_sk = secp_k.secret
        self.reply_pk = secp_k.public_key.format(True)
        assert(len(self.reply_pk) == 33)

    async def get_updated(self, name):
        if name not in self.names:
            t = int(time.time())
            self.names[name] = t
            return t

        while 1:
            t = int(time.time())
            if t == self.names[name]:
                await asyncio.sleep(1)
                continue
            else:
                self.names[name] = t
                return t

    async def get_dest_pipe(self):
        route = self.dest.route.interface.route(self.dest.route.af)
        route = await route.bind()
        pipe = await pipe_open(self.proto, self.dest, route)
        return pipe

    async def return_resp(self, pipe):
        try:
            buf = await proto_recv(pipe)
            buf = decrypt(self.reply_sk, buf)
            pkt = PNPPacket.unpack(buf)
            
            if not pkt.updated:
                pkt.value = None
            return pkt
        except:
            log_exception()
            return None
        finally:
            await pipe.close()

    async def send_pkt(self, pipe, pkt, sign=True):
        pkt.reply_pk = self.reply_pk
        pnp_msg = pkt.get_msg_to_sign()
        if sign:
            sig = self.sk.sign(pnp_msg)
        else:
            sig = b""

        buf = pnp_msg + sig
        enc_msg = encrypt(self.dest_pk, buf)
        end = 1 if self.proto == TCP else 3
        for _ in range(0, end):
            send_success = await pipe.send(enc_msg, self.dest.tup)
            if not send_success:
                log(f"pnp client send pkt failure.")

            if end > 1:
                await asyncio.sleep(0.5)

    async def fetch(self, name):
        pipe = await self.get_dest_pipe()
        pkt = PNPPacket(name, vkc=self.vkc)
        await self.send_pkt(pipe, pkt, sign=False)
        return await self.return_resp(pipe)

    async def push(self, name, value, behavior=BEHAVIOR_DO_BUMP):
        t = await self.get_updated(name)
        pipe = await self.get_dest_pipe()
        pkt = PNPPacket(name, value, self.vkc, None, t, behavior)
        await self.send_pkt(pipe, pkt)
        return await self.return_resp(pipe)

    async def delete(self, name):
        t = await self.get_updated(name)
        pipe = await self.get_dest_pipe()
        pkt = PNPPacket(name, vkc=self.vkc, updated=t)
        await self.send_pkt(pipe, pkt)
        return await self.return_resp(pipe)
