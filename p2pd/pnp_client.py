# TODO: different key per request.

from ecdsa import SECP256k1, SigningKey
from .ecies import decrypt, encrypt
from .pipe_utils import *
from .pnp_utils import *
from .address import *

"""
Important: since this immediately returns if one
were to follow-up with another call without waiting for
status receipt it may return an invalid value
indicating that the server hasn't done the previous call yet.
"""
class PNPClient():
    def __init__(self, sk, dest, dest_pk, nic, sys_clock, proto=TCP):
        self.dest_pk = dest_pk
        assert(isinstance(dest_pk, bytes))
        self.sys_clock = sys_clock
        self.nic = nic
        self.dest = dest
        self.sk = sk
        self.vkc = sk.verifying_key.to_string("compressed")
        self.names = {}
        self.proto = proto
        self.reply_sk = SigningKey.generate(curve=SECP256k1)
        self.reply_pk = self.reply_sk.get_verifying_key().to_string("compressed")
        assert(len(self.reply_pk) == 33)

    async def get_updated(self, name):
        if name not in self.names:
            t = int(self.sys_clock.time())
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
        addr = Address(self.dest[0], self.dest[1])
        await addr.res(self.nic.route())
        ipr = addr.v4_ipr or addr.v6_ipr
        route = self.nic.route(ipr.af)
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
            send_success = await pipe.send(enc_msg, self.dest)
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
