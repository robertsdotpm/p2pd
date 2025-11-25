
import time
import socket
import struct
import selectors
from .....net.ip_range import *
from .....nic.nat.nat_utils import *
from .....nic.nat.nat_predict import *
from .....nic.interface import *
from .....utility.clock_skew import *
from ..punch_defs import *

# --- NTP Constants ---
NTP_SERVER = "pool.ntp.org"
NTP_PORT = 123
NTP_DELTA = 2208988800 # 70-year offset between NTP epoch (1900) and Unix epoch (1970)
NTP_PACKET_SIZE = 48
MAX_NTP_RETRIES = 5
NTP_TIMEOUT = 1.0

def timestamp_from_ntp(server=NTP_SERVER, port=NTP_PORT, retries=MAX_NTP_RETRIES, timeout=NTP_TIMEOUT):
    """
    Fetches the Unix timestamp from an NTP server using UDP sockets, 
    with built-in retry logic for reliability.
    """
    # NTP request message: 48 bytes, setting mode=3 (client), version=4
    # The first byte is 0b00100011 (0x23)
    request_data = b'\x23' + 47 * b'\0' 

    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                # Send the request
                s.sendto(request_data, (server, port))
                # Receive the response
                response_data, _ = s.recvfrom(NTP_PACKET_SIZE)
                
                if len(response_data) < NTP_PACKET_SIZE:
                    raise RuntimeError("NTP response too short")

                # The Transmit Timestamp is the last 8 bytes (offset 40)
                # It is a 64-bit unsigned fixed-point number (seconds + fraction)
                # We unpack the first 4 bytes (seconds part)
                ntp_time_seconds = struct.unpack('!I', response_data[40:44])[0]
                
                # Convert from NTP epoch (1900) to Unix epoch (1970)
                unix_time = ntp_time_seconds - NTP_DELTA
                
                return int(unix_time)

        except socket.timeout:
            print(f"NTP request timed out. Retrying ({attempt + 1}/{retries})...")
            time.sleep(0.1)
        except Exception as e:
            # Handle other socket errors or unpacking issues
            print(f"NTP error on attempt {attempt + 1}: {e}")
            time.sleep(0.1)

    raise RuntimeError(f"Failed to get reliable network time from {server} after {retries} attempts.")

"""
The function bellow is used to adjust sleep parameters
for the punching algorithm. Sleep time is reduced
based on how close the destination is.
"""
def get_punch_mode(af, dest_ip, same_machine):
    cidr = af_to_cidr(af)
    dest_ipr = IPRange(dest_ip, cidr=cidr)

    # Calculate punch mode
    if dest_ipr.is_public:
        return TCP_PUNCH_REMOTE
    else:
        if same_machine:
            return TCP_PUNCH_SELF
        else:
            return TCP_PUNCH_LAN

def punching_sanity_check(mode, our_wan, dest_addr, send_mappings, recv_mappings):
    if mode == TCP_PUNCH_SELF:
        for sm in send_mappings:
            for rm in recv_mappings:
                if sm.local == rm.local:
                    error = \
                    fstr("punch self local port conflict ")
                    fstr("{0} {1}", (sm.local, rm.local,))
                    log(error)

    if mode == TCP_PUNCH_REMOTE:
        if our_wan == dest_addr:
            error = \
            fstr("punch remote but dest is the same ")
            fstr("as our ext {0}", (our_wan,))
            log(error)
            
# Not really the best approach but process communication is a pain.
async def punch_close_msg(msg, client_tup, pipe):
    if msg in PUNCH_END:
        # Allow time to send message down pipes.
        await asyncio.sleep(2)
        await pipe.close()

async def setup_punch_coordination(node, sys_clock=None):
    if sys_clock is None:
        sys_clock = await SysClock(node.ifs[0]).start()

    node.max_punchers, node.pp_executor = await get_pp_executors()
    node.sys_clock = sys_clock

def wait_for_one_remaining(sockets, timeout=5.0):
    """
    Waits up to 5 seconds for all but one socket to close.
    Does NOT close the sockets locally.
    """
    sel = selectors.DefaultSelector()
    remaining = set(sockets)
    
    for s in sockets:
        sel.register(s, selectors.EVENT_READ)

    deadline = time.monotonic() + timeout
    while len(remaining) > 1:
        wait_time = deadline - time.monotonic()
        if wait_time <= 0:
            break # Hard stop at 5 seconds

        events = sel.select(timeout=wait_time)
        for key, _ in events:
            s = key.fileobj
            try:
                # Peek to see if it's empty (closed) without consuming data
                if s.recv(1, socket.MSG_PEEK) == b"":
                    remaining.discard(s)
                    sel.unregister(s)
            except Exception:
                # Any error (connection reset, etc) counts as "gone"
                remaining.discard(s)
                sel.unregister(s)

    sel.close()
    
    # Return the winner, or None if everyone died/timed out
    return list(remaining)[0] if remaining else None

# In a LAN = lan ip, or for WAN targets = wan IPs.
def choose_winning_tcp_sock(their_ip, sock_list, our_ip=None):
    if not sock_list:
        return None

    our_ip = our_ip or sock_list[0].getsockname()[0]

    # Master side closes all others immediately
    if hash(our_ip) > hash(their_ip):
        winner = sock_list.pop()
        for loser in sock_list:
            try:
                loser.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass

            loser.close()
    else:
        # Non-master side waits for the first completed connection
        winner = wait_for_one_remaining(sock_list)

    return winner