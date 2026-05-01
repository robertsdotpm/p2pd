"""
Prefer IPv6 as it will potentially have fewer bumping from dynamic swapping across a shared IPv4 if there's
multiple ifaces; Otherwise use what we've got

python3 run_pnp_serv.py
"""

from typing import Any, List, Optional, Tuple
import asyncio
import time
from aionetiface import (
    to_s, to_b, fstr, log, log_exception, h_to_b,
    DUEL_STACK, IP4, IP6, PNP_SERVERS, VALID_AFS,
    strip_none, async_wrap_errors, SigningKey,
)
import namebump
from ..errors import StartNodeNicknameFailed


# Timestamp envelope for PNP record values. Wraps the payload with a
# magic prefix + 8-byte big-endian unix timestamp so peers can detect
# stale records (e.g. node that died, public-key got rotated, dest
# behind a partition that hasn't refreshed its put). Records written
# before this envelope existed don't have the prefix and are treated
# as ts=0 ("indefinitely old") so the staleness filter only flags
# them when a min_fresh_secs is requested.
PNP_TS_MAGIC = b"PNP1"
PNP_TS_HEADER_LEN = 12  # 4 magic + 8 timestamp


def pnp_wrap_with_ts(value: Any, ts: Optional[int] = None) -> bytes:
    """Prefix value with a timestamp envelope for staleness detection."""
    if ts is None:
        ts = int(time.time())
    return PNP_TS_MAGIC + ts.to_bytes(8, "big") + to_b(value)


def pnp_unwrap_ts(value: Any) -> Tuple[int, Any]:
    """Split a (possibly wrapped) PNP value into (timestamp, payload).

    Returns (0, value) if the value isn't in the wrapped format -- this
    keeps callers backwards-compatible with records that pre-date the
    envelope. ts=0 means "unknown / treat as very old"; only records
    with a ts > 0 survive a non-zero min_fresh_secs filter.
    """
    if not isinstance(value, (bytes, bytearray)):
        return 0, value
    if len(value) < PNP_TS_HEADER_LEN or bytes(value[:4]) != PNP_TS_MAGIC:
        return 0, value
    ts = int.from_bytes(bytes(value[4:12]), "big")
    return ts, bytes(value[12:])

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
# Note: per-server retry now lives inside namebump.Client (with_retry).
# Each call to client.put / get / delete already retries DEFAULT_RETRIES
# times on transient network errors before propagating the exception.
# Nickname methods therefore do not need their own retry loop; the
# NAMING_TIMEOUT bound here applies across all of namebump's retries.


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
        """Store value under name on all reachable PNP servers and return the resulting name with TLD.

        The stored bytes are wrapped with a timestamp envelope (magic
        prefix + unix ts) so readers can filter by staleness via
        Nickname.get(min_fresh_secs=...). Callers pass the raw payload
        (e.g. addr_bytes); the envelope is added here.
        """
        if not self.started:
            raise AssertionError("Nickname client not started. Call start() first.")
        name = pnp_strip_tlds(name)
        log(fstr("Nickname.put: name={0} timeout={1}", (name, timeout)))

        # Wrap the value with the freshness envelope. The timestamp
        # written here is what Nickname.get(min_fresh_secs=...) checks
        # against -- a writer with a wildly skewed clock would produce
        # records that look "from the future" or "indefinitely old"
        # depending on direction. The matrix VMs have NTP-aligned
        # clocks so this isn't a concern in practice; for hosts
        # without working NTP the staleness filter degrades to "treat
        # all wrapped records as fresh" which is the same as the
        # legacy unwrapped behaviour.
        wrapped_value = pnp_wrap_with_ts(value)

        # Single coro for storing at one server. namebump.Client.put
        # retries internally on transient network errors, so this worker
        # only needs to walk the AFs and surface any non-network failure.
        async def worker(offset: int) -> Optional[int]:
            """Attempt to store the name on the PNP server at offset and return offset on success."""
            import time as _time
            for af in VALID_AFS:
                t0 = _time.time()
                try:
                    client = self.clients[af][offset]
                    if client is None:
                        log(fstr(
                            "Nickname.put: offset={0} af={1} client=None (skip)",
                            (offset, af),
                        ))
                        continue
                    log(fstr(
                        "Nickname.put: offset={0} af={1} -> client.put",
                        (offset, af),
                    ))
                    ret = await client.put(name, wrapped_value, client.kp, behavior)
                    dt = int((_time.time() - t0) * 1000)
                    if ret is None:
                        log(fstr(
                            "Nickname.put: offset={0} af={1} ret=None elapsed_ms={2} (continue)",
                            (offset, af, dt),
                        ))
                        continue
                    if ret.value is not None:
                        log(fstr(
                            "Nickname.put: offset={0} af={1} success elapsed_ms={2}",
                            (offset, af, dt),
                        ))
                        return offset
                    log(fstr(
                        "Nickname.put: offset={0} af={1} value=None elapsed_ms={2} (server rejected)",
                        (offset, af, dt),
                    ))
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    log_exception()
                    log(fstr(
                        "Nickname.put: offset={0} af={1} network error elapsed_ms={2}",
                        (offset, af, int((_time.time() - t0) * 1000)),
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

    async def get(
        self,
        name: Any,
        timeout: int = NAMING_TIMEOUT,
        min_fresh_secs: int = 0,
    ) -> Optional[Any]:
        """Look up name on the authoritative PNP servers and return the first successful result.

        min_fresh_secs > 0 enables staleness filtering. The stored
        record's timestamp must be within (now - min_fresh_secs)
        seconds for the result to be returned; older records are
        skipped and the next server / next iteration is tried.
        Records written without the freshness envelope (legacy data
        that pre-dates pnp_wrap_with_ts) report ts=0 and pass through
        the filter only when min_fresh_secs == 0.

        On a successful return, ret.value is the unwrapped payload
        (envelope stripped) and ret.pnp_ts is set to the record's
        timestamp (0 for legacy records).
        """
        if not self.started:
            raise AssertionError("Nickname client not started. Call start() first.")

        async def worker(offset: int, name: Any) -> Optional[Any]:
            """Query the PNP server at offset for name and return the first non-None record."""
            import time as _time
            for af in VALID_AFS:
                t0 = _time.time()
                try:
                    client = self.clients[af][offset]
                    if client is None:
                        log(fstr(
                            "Nickname.get: offset={0} af={1} client=None (skip)",
                            (offset, af),
                        ))
                        continue
                    log(fstr(
                        "Nickname.get: offset={0} af={1} -> client.get",
                        (offset, af),
                    ))
                    ret = await client.get(name)
                    dt = _time.time() - t0
                    has_val = ret is not None and ret.value is not None
                    log(fstr(
                        "Nickname.get: offset={0} af={1} ret_value_present={2} elapsed_ms={3}",
                        (offset, af, has_val, int(dt * 1000)),
                    ))
                    if ret is not None:
                        # Unwrap freshness envelope. Legacy unwrapped
                        # records report ts=0; ret.value is replaced
                        # with the bare payload either way so callers
                        # don't see the envelope bytes.
                        if ret.value is not None:
                            ts, payload = pnp_unwrap_ts(ret.value)
                            ret.value = payload
                            ret.pnp_ts = ts
                            if min_fresh_secs > 0:
                                age = int(_time.time()) - ts if ts else None
                                if ts == 0 or age > min_fresh_secs:
                                    log(fstr(
                                        "Nickname.get: offset={0} af={1} stale "
                                        "ts={2} age={3}s threshold={4}s "
                                        "(skipping)",
                                        (offset, af, ts, age, min_fresh_secs),
                                    ))
                                    continue
                        else:
                            ret.pnp_ts = 0
                        return ret
                except asyncio.CancelledError:  # pylint: disable=try-except-raise
                    raise
                except (OSError, ConnectionError, asyncio.TimeoutError):
                    log_exception()
                    log(fstr(
                        "Nickname.get: offset={0} af={1} network error elapsed_ms={2}",
                        (offset, af, int((_time.time() - t0) * 1000)),
                    ))

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
