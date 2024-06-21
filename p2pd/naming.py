"""
Prefer IPv6 as it will potentially have fewer bumping from dynamic swapping across a shared IPv4 if there's
multiple ifaces; Otherwise use what we've got
"""

from .settings import *
from .utils import *
from .pnp_client import *
from .interface import *
from ecdsa import SigningKey

NAMING_TIMEOUT = 1.0

class PartialNameSuccess(Exception):
    pass

class FullNameFailure(Exception):
    pass

class Naming():
    def __init__(self, sk_hex, interface):
        self.sk = SigningKey.from_string(h_to_b(sk_hex))
        self.interface = interface
        self.clients = []

    async def start(self):
        if IP6 in self.interface.supported():
            af = IP6
        else:
            af = IP4

        for serv_info in PNP_SERVERS[af]:
            print(serv_info["ip"])
            dest = await Address(
                serv_info["ip"],
                serv_info["port"],
                self.interface.route(af)
            )

            self.clients.append(
                PNPClient(
                    self.sk,
                    dest,
                    serv_info["pk"]
                )
            )

    async def do_client_actions_concurrently(self, action_s, action_p, timeout=NAMING_TIMEOUT):
        tasks = []
        for client in self.clients:
            action = eval(f"client.{action_s}")
            task = action(*action_p)
            tasks.append(task)

        success_no = 0
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks),
                timeout
            )

            for pkt in results:
                if pkt is None:
                    continue
                if pkt.value is None:
                    continue

                success_no += 1
        except asyncio.TimeoutError:
            success_no = 0

        if success_no == 0:
            raise FullNameFailure("Name action failed. All servers down.")
        
        if success_no and success_no != len(results):
            raise PartialNameSuccess("Some name actions to register across servers.")

    async def fetch(self, name, timeout=NAMING_TIMEOUT):
        tasks = []
        for client in self.clients:
            task = client.fetch(name)
            tasks.append(task)

        for task in asyncio.as_completed(tasks, timeout=timeout):
            pkt = await task
            if pkt.value is not None:
                return pkt

    async def push(self, name, value, behavior=BEHAVIOR_DO_BUMP, timeout=NAMING_TIMEOUT):
        return await self.do_client_actions_concurrently(
            "push",
            (name, value, behavior,),
            timeout
        )

    async def delete(self, name, timeout=NAMING_TIMEOUT):
        return await self.do_client_actions_concurrently(
            "delete",
            (name,),
            timeout
        )


async def workspace():
    TEST_SK = b'\xfe\xb1w~v\xfe\xc4:\x83\xa6C\x19\xde\x11\xc2\xc8\xc4A\xdaEC\x01\xc2\x9d'
    TEST_SK = (b"12345" * 100)[:24]
    test_sk_hex = to_h(TEST_SK)
    i = await Interface()
    print(i)

    name = "my_test_name3"
    n = Naming(test_sk_hex, i)
    await n.start()
    await n.push(name, "some test val")

    return
    out = await n.fetch(name)
    print(out.value)

    await n.delete(name)
    out = await n.fetch(name)
    print(out)

    await asyncio.sleep(2)

async_test(workspace)