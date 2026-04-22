"""Low-level helpers for the punch engine."""
from typing import Any, List, Optional
import time
import socket
import struct
import selectors
import asyncio
from aionetiface import IPRange, fstr, log, SysClock
from ..punch_defs import *

# --- NTP Constants ---
NTP_SERVER = "pool.ntp.org"
NTP_PORT = 123
NTP_DELTA = 2208988800  # 70-year offset between NTP epoch (1900) and Unix epoch (1970)
NTP_PACKET_SIZE = 48
MAX_NTP_RETRIES = 5
NTP_TIMEOUT = 1.0


def timestamp_from_ntp(
server: str = NTP_SERVER,
    port: int = NTP_PORT,
    retries: int = MAX_NTP_RETRIES,
    timeout: float = NTP_TIMEOUT,
) -> int:
    """
    Fetches the Unix timestamp from an NTP server using UDP sockets,
    with built-in retry logic for reliability.
    """
    # NTP request message: 48 bytes, setting mode=3 (client), version=4
    # The first byte is 0b00100011 (0x23)
    request_data = b"\x23" + 47 * b"\0"

    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                # Send the request
                s.sendto(request_data, (server, port))
                # Receive the response
                response_data, _ = s.recvfrom(NTP_PACKET_SIZE)

                if len(response_data) < NTP_PACKET_SIZE:
                    raise ValueError("NTP response too short")

                # The Transmit Timestamp is the last 8 bytes (offset 40)
                # It is a 64-bit unsigned fixed-point number (seconds + fraction)
                # We unpack the first 4 bytes (seconds part)
                ntp_time_seconds = struct.unpack("!I", response_data[40:44])[0]

                # Convert from NTP epoch (1900) to Unix epoch (1970)
                unix_time = ntp_time_seconds - NTP_DELTA

                return int(unix_time)

        except socket.timeout:
            time.sleep(0.1)
        except (OSError, struct.error):
            # Handle other socket errors or unpacking issues
            time.sleep(0.1)

    raise OSError("Failed to get reliable network time")


"""
The function bellow is used to adjust sleep parameters
for the punching algorithm. Sleep time is reduced
based on how close the destination is.
"""


def get_punch_mode(af: Any, dest_ip: str, same_machine: bool) -> int:
    """Return the punch mode constant (remote, LAN, or self) for the given destination IP."""
    host_limit = 0
    dest_ipr = IPRange(dest_ip, bitlen=host_limit)

    # Calculate punch mode
    if dest_ipr.is_public:
        return TCP_PUNCH_REMOTE
    else:
        if same_machine:
            return TCP_PUNCH_SELF
        else:
            return TCP_PUNCH_LAN


def punching_sanity_check(mode: int, our_wan: Any, dest_addr: str, send_mappings: List[Any], recv_mappings: List[Any]) -> None:
    """Log warnings when port or address conflicts are detected in the punch configuration."""
    if mode == TCP_PUNCH_SELF:
        for sm in send_mappings:
            for rm in recv_mappings:
                if sm.local == rm.local:
                    error = fstr("punch self local port conflict ")
                    fstr(
                        "{0} {1}",
                        (
                            sm.local,
                            rm.local,
                        ),
                    )
                    log(error)

    if mode == TCP_PUNCH_REMOTE:
        if our_wan == dest_addr:
            error = fstr("punch remote but dest is the same ")
            fstr("as our ext {0}", (our_wan,))
            log(error)


# Not really the best approach but process communication is a pain.
async def punch_close_msg(msg: bytes, client_tup: Any, pipe: Any) -> None:
    """Close the pipe after a short delay when a punch-end message is received."""
    if msg in PUNCH_END:
        # Allow time to send message down pipes.
        await asyncio.sleep(2)
        await pipe.close()


async def setup_punch_coordination(node: Any, sys_clock: Optional[Any] = None) -> None:
    """Initialise and attach the NTP-synchronised SysClock to the node for punch timing."""
    if sys_clock is None:
        sys_clock = await SysClock(node.ifs[0]).start()

    node.sys_clock = sys_clock


def wait_for_one_remaining(sockets: List[Any], timeout: float = 5.0) -> Optional[Any]:
    """
    Waits up to 5 seconds for all but one socket to close.
    Does NOT close the sockets locally.
    """
    sel = selectors.DefaultSelector()
    remaining = set(sockets)

    for s in sockets:
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ)

    deadline = time.monotonic() + timeout
    while len(remaining) > 1:
        wait_time = deadline - time.monotonic()
        if wait_time <= 0:
            break  # Hard stop at 5 seconds

        events = sel.select(timeout=wait_time)
        for key, _ in events:
            s = key.fileobj
            try:
                # recv() returning b"" is the canonical EOF signal
                data = s.recv(4096)
                if data == b"":
                    remaining.discard(s)
                    try:
                        sel.unregister(s)
                    except OSError:
                        pass
            except OSError:
                # Any error (connection reset, etc) counts as "gone"
                remaining.discard(s)
                try:
                    sel.unregister(s)
                except OSError:
                    pass

    sel.close()

    # Return the winner, or None if everyone died/timed out
    return list(remaining)[0] if remaining else None


def wait_for_first_with_data(sockets: List[Any], timeout: float = 5.0) -> Optional[Any]:
    """
    Wait until one of the sockets has data, then read and return it.
    Returns (socket, data) or (None, None) if timed out.
    """
    sel = selectors.DefaultSelector()

    for s in sockets:
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ)

    deadline = time.monotonic() + timeout
    try:
        while True:
            wait_time = deadline - time.monotonic()
            if wait_time <= 0:
                return None

            events = sel.select(timeout=wait_time)
            if not events:
                return None

            for key, _ in events:
                s = key.fileobj
                try:
                    data = s.recv(1)
                    if data:  # data available
                        return s
                    # else: recv returned 0 → socket closed
                    # let caller handle it if needed
                except BlockingIOError:
                    continue  # not actually ready
                except OSError:
                    continue  # ignore closed/reset sockets
    finally:
        sel.close()


# In a LAN = lan ip, or for WAN targets = wan IPs.
def choose_winning_tcp_sock(their_ip: str, sock_list: List[Any], our_ip: Optional[str] = None) -> Optional[Any]:
    """Select one winning socket from a punched connection set, closing the rest."""
    # No open sockets.
    if not sock_list:
        return None

    # Master side closes all others immediately
    our_ip = our_ip or sock_list[0].getsockname()[0]
    if our_ip > their_ip:
        winner = sock_list.pop()
        winner.send(b"$")
        for loser in sock_list:
            try:
                loser.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

            loser.close()
    else:
        # Non-master side waits for the first completed connection
        winner = wait_for_first_with_data(sock_list)

    return winner
