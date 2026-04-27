"""
Shared helpers for tests that talk to flaky 3rd-party services.

The Nickname / STUN / TURN servers we test against are real public
infrastructure -- they go up and down, hit per-IP quotas, and
occasionally rate-limit. Tests that hardcode a single server (or
even a single name) flake whenever that one path goes wrong, even
when alternate servers in the rendezvous-hash pool would succeed.

Two helpers, both warn-on-flake-friendly:

  * with_server_retry(coro_factory)  -- run an async op, retrying on
    transient network errors. Useful when the underlying client (e.g.
    Nickname) already iterates servers but the test wants outer-loop
    retry on top.

  * try_servers(servers, factory)    -- given a list of server tuples,
    walk them in order, return the first that yields a working client.
    Useful when the test explicitly picks ONE server and we want it
    to fall through on outage.

Both helpers self.skipTest with a clear ENV reason when every
attempt fails. That keeps the matrix gate green on third-party
flakes without masking real client regressions (which surface as
exception types not in the retry filter).
"""
from typing import Any, Callable, Iterable, List, Optional
import asyncio


# Errors we treat as "try again with a different server / name".
# Application errors (KeyError, AssertionError, ValueError) are NOT
# in this set so a real client bug still raises out of the retry loop.
TRANSIENT_ERRORS = (OSError, ConnectionError, asyncio.TimeoutError)


async def with_server_retry(
    coro_factory: Callable[[], Any],
    attempts: int = 3,
    pause: float = 0.5,
    extra_errors: Optional[tuple] = None,
) -> Any:
    """Run coro_factory() up to attempts times, retrying on transient errors.

    coro_factory is a zero-arg callable that returns a fresh coroutine
    each call. Retries on (OSError, ConnectionError, TimeoutError) plus
    any extra exception types in extra_errors. Use extra_errors to add
    e.g. namebump's FullNameFailure or PNP's resource-exhaustion errors
    to the retry set without polluting the default for unrelated tests.

    pause is the delay between retries (seconds). Linear, not
    exponential -- we're trying alternates not waiting out a backoff.
    """
    errors = TRANSIENT_ERRORS
    if extra_errors:
        errors = errors + tuple(extra_errors)

    last_exc = None
    for i in range(attempts):
        try:
            return await coro_factory()
        except errors as exc:
            last_exc = exc
            if i + 1 < attempts:
                await asyncio.sleep(pause)
    if last_exc is not None:
        raise last_exc
    raise ConnectionError("with_server_retry: all attempts exhausted")


async def try_servers(
    servers: Iterable[Any],
    factory: Callable[[Any], Any],
    extra_errors: Optional[tuple] = None,
) -> Any:
    """Walk servers, return the first factory(server) that succeeds.

    factory(server) is awaitable; treat (OSError, ConnectionError,
    TimeoutError) plus extra_errors as "try the next server". When
    every server fails, raise the last error so the test surface
    sees a meaningful exception (test code can catch + skipTest).

    Use this when a test explicitly picks one server from a list and
    wants graceful fallthrough -- e.g. test_status.TestStatus's TURN
    iteration where the live code already loops the host list but
    doesn't propagate the "first working" choice.
    """
    errors = TRANSIENT_ERRORS
    if extra_errors:
        errors = errors + tuple(extra_errors)

    server_list = list(servers)
    if not server_list:
        raise ValueError("try_servers: empty server list")

    last_exc = None
    for server in server_list:
        try:
            return await factory(server)
        except errors as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise ConnectionError("try_servers: every server failed")
