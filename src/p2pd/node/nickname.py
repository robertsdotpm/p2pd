"""
Prefer IPv6 as it will potentially have fewer bumping from dynamic swapping across a shared IPv4 if there's
multiple ifaces; Otherwise use what we've got

python3 run_pnp_serv.py
"""

from typing import Any, List, Optional, Tuple
import asyncio
from aionetiface import (
    to_s, fstr, log, log_exception, h_to_b,
    DUEL_STACK, IP4, IP6, PNP_SERVERS, VALID_AFS,
    strip_none, async_wrap_errors, SigningKey,
)
import namebump
from ..errors import StartNodeNicknameFailed

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


def pnp_get_tld(offsets: List[int]) -> str:
    """Return the PNP TLD string (e.g. '.peer') corresponding to the given server index list."""
    index = frozenset(offsets)
    return PNP_INDEX_TO_TLD[index]


def pnp_get_offsets(tld: str) -> List[int]:
    """Return the list of PNP server offsets that must hold a record for the given TLD."""
    index = PNP_TLD_TO_INDEX[tld]
    return list(index)


def pnp_strip_tlds(name: Any) -> str:
    """Strip any known PNP TLD suffix from name and return the bare label."""
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


def pnp_name_has_tld(name: Any) -> bool:
    """Return True if name ends with a recognised PNP TLD suffix."""
    name = to_s(name)
    for tld in PNP_TLD_TO_INDEX:
        portion = name[-len(tld) :]
        if portion == tld:
            return True

    return False


NAMING_TIMEOUT = 10

# Per-server retry. namebump.Client itself has no retries -- a single hung
# server response would otherwise eat the whole NAMING_TIMEOUT and fail
# the operation. Three attempts with a short pause between them gives a
# transient slow server a chance without inflating a healthy call's
# best-case latency.
NAMING_RETRIES = 3
NAMING_RETRY_PAUSE = 0.5


class PartialNameSuccess(Exception):
    """Raised when a nickname was registered on some but not all PNP servers."""


class FullNameFailure(Exception):
    """Raised when a nickname registration failed on all PNP servers."""


class Nickname:
    """Manages PNP nickname registration and lookup for a P2P node."""

    def __init__(self, sk: SigningKey, ifs: List[Any], sys_clock: Any) -> None:
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

    async def start(self, timeout: int = 2) -> "Nickname":
        """Connect to all reachable PNP servers and mark the client as started."""
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

                async def job(af: Any = af, index: int = index, client: Any = client) -> Tuple[Any, int, Optional[Any]]:
                    """Start the namebump client and verify connectivity, returning (af, index, client)."""
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

    async def put(self, name: Any, value: Any, behavior: Any = namebump.DO_BUMP, timeout: int = NAMING_TIMEOUT) -> str:
        """Store value under name on all reachable PNP servers and return the resulting name with TLD."""
        if not self.started:
            raise AssertionError("Nickname client not started. Call start() first.")
        name = pnp_strip_tlds(name)
        log(fstr(
            "Nickname.put: name={0} timeout={1} retries={2}",
            (name, timeout, NAMING_RETRIES),
        ))

        # Single coro for storing at one server. Retries each attempt
        # NAMING_RETRIES times with NAMING_RETRY_PAUSE between, since
        # namebump itself has no retry layer.
        async def worker(offset: int) -> Optional[int]:
            """Attempt to store the name on the PNP server at offset and return offset on success."""
            for attempt in range(NAMING_RETRIES):
                for af in VALID_AFS:
                    try:
                        client = self.clients[af][offset]
                        if client is None:
                            continue
                        log(fstr(
                            "Nickname.put: offset={0} af={1} attempt={2} -> client.put",
                            (offset, af, attempt),
                        ))
                        ret = await client.put(name, value, client.kp, behavior)
                        if ret is None:
                            log(fstr(
                                "Nickname.put: offset={0} af={1} attempt={2} ret=None (continue)",
                                (offset, af, attempt),
                            ))
                            continue
                        if ret.value is not None:
                            log(fstr(
                                "Nickname.put: offset={0} af={1} attempt={2} success",
                                (offset, af, attempt),
                            ))
                            return offset
                    except (OSError, ConnectionError, asyncio.TimeoutError):
                        log_exception()
                if attempt + 1 < NAMING_RETRIES:
                    await asyncio.sleep(NAMING_RETRY_PAUSE)
            log(fstr(
                "Nickname.put: offset={0} exhausted {1} attempts",
                (offset, NAMING_RETRIES),
            ))
            return None

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
        log(fstr("Nickname.put: gathering {0} workers", (len(tasks),)))
        results = await asyncio.gather(*tasks)
        log(fstr("Nickname.put: gather done, results={0}", (results,)))
        offsets = strip_none(results)
        if not offsets:
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

    async def get(self, name: Any, timeout: int = NAMING_TIMEOUT) -> Optional[Any]:
        """Look up name on the authoritative PNP servers and return the first successful result."""
        if not self.started:
            raise AssertionError("Nickname client not started. Call start() first.")

        async def worker(offset: int, name: Any) -> Optional[Any]:
            """Query the PNP server at offset for name and return the first non-None record."""
            for af in VALID_AFS:
                try:
                    client = self.clients[af][offset]
                    if client is None:
                        continue
                    ret = await client.get(name)
                    if ret is not None:
                        return ret
                except asyncio.CancelledError:  # pylint: disable=try-except-raise
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

    async def delete(self, name: Any, timeout: int = NAMING_TIMEOUT) -> None:
        """Delete the record for name from all reachable PNP servers concurrently."""
        if not self.started:
            raise AssertionError("Nickname client not started. Call start() first.")
        name = pnp_strip_tlds(name)

        async def worker(offset: int) -> Optional[Any]:
            """Send a delete request for name to the PNP server at offset and return the result."""
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

    async def close(self) -> None:
        """Close all active PNP client connections and reset the started flag."""
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

    async def __aenter__(self) -> "Nickname":
        await self.start()
        return self

    async def __aexit__(self, *_) -> bool:
        await self.close()
        return False

    def __await__(self) -> Any:
        return self.start().__await__()


# push:
#     - try to store on all of them
#     - store success offsets
#     - convert success offsets to tld
#     - return name + tld on success
#
# fetch:
#     - name + tld
#     - convert to list of offsets
#     - use first in to get the fastest success result
#
# delete:
#     - name + tld
#     - convert to list of offsets
#     - concurrently delete them
#     - no follow up
