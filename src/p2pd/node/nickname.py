"""
Prefer IPv6 as it will potentially have fewer bumping from dynamic swapping across a shared IPv4 if there's
multiple ifaces; Otherwise use what we've got

python3 run_pnp_serv.py
"""

from aionetiface import *
import namebump
from ..errors import *

PNP_INDEX_TO_TLD = {
    frozenset([0]): ".p2p",
    frozenset([1]): ".node",
    frozenset([0, 1]): ".peer",
}

PNP_TLD_TO_INDEX = {
    ".p2p": frozenset([0]),
    ".node": frozenset([1]),
    ".peer": frozenset([0, 1]),
}


def pnp_get_tld(offsets):
    # type: (List[int]) -> str
    index = frozenset(offsets)
    return PNP_INDEX_TO_TLD[index]


def pnp_get_offsets(tld):
    # type: (str) -> List[int]
    index = PNP_TLD_TO_INDEX[tld]
    return list(index)


def pnp_strip_tlds(name):
    # type: (Any) -> str
    name = to_s(name)
    for tld in PNP_TLD_TO_INDEX:
        # Grab the last len(tld) characters in name.
        # Underflows will grab everything.
        portion = name[-len(tld) :]

        # TLD found so strip it.
        # Underflows set the str to "" empty.
        if portion == tld:
            name = name[: -len(tld)]
            break

    return name


def pnp_name_has_tld(name):
    # type: (Any) -> bool
    name = to_s(name)
    for tld in PNP_TLD_TO_INDEX:
        portion = name[-len(tld) :]
        if portion == tld:
            return True

    return False


NAMING_TIMEOUT = 10


class PartialNameSuccess(Exception):
    """Raised when a nickname was registered on some but not all PNP servers."""

    pass


class FullNameFailure(Exception):
    """Raised when a nickname registration failed on all PNP servers."""

    pass


class Nickname:
    """Manages PNP nickname registration and lookup for a P2P node."""

    def __init__(self, sk, ifs, sys_clock):
        # type: (SigningKey, List[Any], Any) -> None
        self.sk = sk
        self.ifs = ifs
        self.sys_clock = sys_clock

        # Select best NIC from if list to be primary NIC.
        for preferred_stack in [DUEL_STACK, IP4, IP6]:
            break_all = False
            for nic in self.ifs:
                if nic.stack == preferred_stack:
                    self.interface = nic
                    break_all = True
                    break

            if break_all:
                break

        self.clients = {IP4: {}, IP6: {}}
        self.started = False

    async def start(self, timeout=2):
        # type: (int) -> Nickname
        tasks = []

        for index in range(len(PNP_SERVERS[IP4])):
            for af in [IP4, IP6]:
                if af not in self.interface.supported():
                    self.clients[af][index] = None
                    continue

                serv_info = PNP_SERVERS[af][index]
                dest = (serv_info["ip"], serv_info["port"])
                client = namebump.Client(
                    dest,
                    h_to_b(serv_info["pk"]),
                    sys_clock=self.sys_clock,
                    nic=self.interface,
                )
                client.kp = namebump.Keypair(self.sk)

                async def job(af=af, index=index, client=client):
                    # type: (Any, int, Any) -> Tuple[Any, int, Optional[Any]]
                    pipe = None
                    try:
                        await client.start()
                        pipe = await asyncio.wait_for(
                            client.get_dest_pipe(), timeout=timeout
                        )
                        if pipe is None:
                            return (af, index, None)
                    except (OSError, ConnectionError, asyncio.TimeoutError):
                        log_exception()
                        return (af, index, None)
                    finally:
                        if pipe is not None:
                            await pipe.close()
                    return (af, index, client)

                tasks.append(asyncio.create_task(job()))

        results = await asyncio.gather(*tasks, return_exceptions=False)

        success_no = 0
        for af, index, client in results:
            self.clients[af][index] = client
            if client is not None:
                success_no += 1

        if not success_no:
            raise StartNodeNicknameFailed()

        self.started = True
        return self

    async def put(self, name, value, behavior=namebump.DO_BUMP, timeout=NAMING_TIMEOUT):
        # type: (Any, Any, Any, int) -> str
        if not self.started:
            raise RuntimeError("Nickname client not started. Call start() first.")
        name = pnp_strip_tlds(name)

        # Single coro for storing at one server.
        async def worker(offset):
            # type: (int) -> Optional[int]
            for af in VALID_AFS:
                try:
                    client = self.clients[af][offset]
                    if client is None:
                        continue
                    ret = await client.put(name, value, client.kp, behavior)
                    if ret is None:
                        continue
                    if ret.value is not None:
                        return offset
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    log_exception()

        # Schedule store tasks at all PNP servers.
        tasks = []
        for offset in range(0, len(self.clients[IP4])):
            tasks.append(
                async_wrap_errors(
                    worker(offset),
                    timeout,
                )
            )

        # Attempt storage at all PNP servers.
        results = await asyncio.gather(*tasks)
        offsets = strip_none(results)
        if not len(offsets):
            raise FullNameFailure("All name servers failed.")

        # Translate success offsets into specific TLD.
        tld = pnp_get_tld(offsets)
        return fstr(
            "{0}{1}",
            (
                name,
                tld,
            ),
        )

    async def get(self, name, timeout=NAMING_TIMEOUT):
        # type: (Any, int) -> Optional[Any]
        if not self.started:
            raise RuntimeError("Nickname client not started. Call start() first.")

        async def worker(offset, name):
            # type: (int, Any) -> Optional[Any]
            for af in VALID_AFS:
                try:
                    client = self.clients[af][offset]
                    if client is None:
                        continue
                    ret = await client.get(name)
                    if ret is not None:
                        return ret
                except asyncio.CancelledError:
                    raise
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    log_exception()

        # Convert TLD to client offset list.
        tld = "." + name.split(".")[-1]
        offsets = pnp_get_offsets(tld)
        name = name[: -len(tld)]

        # Build concurrent fetch tasks.
        tasks = []
        for offset in offsets:
            tasks.append(async_wrap_errors(worker(offset, name), timeout))

        # Return first success. Outer timeout is a safety net in case
        # async_wrap_errors doesn't catch a hanging task.
        t = timeout + 1
        first_in = asyncio.as_completed(tasks, timeout=t)
        try:
            for task in first_in:
                ret = await task
                if ret is not None and ret.value is not None:
                    return ret
        except asyncio.TimeoutError:
            pass

        raise FullNameFailure(fstr("Could not fetch {0}", (name,)))

    async def delete(self, name, timeout=NAMING_TIMEOUT):
        # type: (Any, int) -> None
        if not self.started:
            raise RuntimeError("Nickname client not started. Call start() first.")
        name = pnp_strip_tlds(name)

        async def worker(offset):
            # type: (int) -> Optional[Any]
            for af in VALID_AFS:
                try:
                    client = self.clients[af][offset]
                    if client is None:
                        continue
                    ret = await client.delete(name, client.kp)
                    if ret is not None:
                        return ret
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    log_exception()

        tasks = []
        for offset in range(0, len(self.clients[IP4])):
            tasks.append(async_wrap_errors(worker(offset), timeout))

        await asyncio.gather(*tasks)

    async def close(self):
        # type: () -> None
        for af in self.clients:
            for index in list(self.clients[af]):
                client = self.clients[af][index]
                if client is not None and hasattr(client, "close"):
                    try:
                        await client.close()
                    except (OSError, asyncio.TimeoutError):
                        pass
                self.clients[af][index] = None
        self.started = False

    async def __aenter__(self):
        # type: () -> Nickname
        await self.start()
        return self

    async def __aexit__(self, *_):
        # type: (Any) -> bool
        await self.close()
        return False

    def __await__(self):
        # type: () -> Any
        return self.start().__await__()


async def workspace():
    # type: () -> None
    return
    TEST_SK = (
        b"\xfe\xb1w~v\xfe\xc4:\x83\xa6C\x19\xde\x11\xc2\xc8\xc4A\xdaEC\x01\xc2\x9d"
    )
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


"""
push:
    - try to store on all of them
    - store success offsets
    - convert success offsets to tld
    - return name + tld on success

fetch:
    - name + tld
    - convert to list of offsets
    - use first in to get the fastest success result

delete:
    - name + tld
    - convert to list of offsets
    - concurrently delete them
    - no follow up


"""
