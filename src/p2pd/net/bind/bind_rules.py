import asyncio
import socket
import platform
from ...utility.utils import *
from ..net_utils import *
from .bind_utils import *

# --- Reusable Logic Functions ---

def get_bind_magic_table(af):
    """
    Generates the table of edge-cases for bind() across platforms and AFs.
    """
    return [
        # Bypasses the need for interface details for localhost binds.
        ["*", VALID_AFS, IP_APPEND, VALID_LOCALHOST, LOCALHOST_LOOKUP[af], ""],

        # No interface added to IP for V6 ANY.
        ["*", IP6, IP_APPEND, V6_VALID_ANY, "::", ""],

        # Make sure to normalize unusual bind all values for v4.
        ["*", IP4, IP_APPEND, V4_VALID_ANY, "0.0.0.0", ""],

        # Windows needs the nic no added to v6 private IPs.
        ["Windows", IP6, IP_APPEND, IP_PRIVATE, "", "nic_id"],

        # ... whereas other operating systems use the interface name.
        ["*", IP6, IP_APPEND, IP_PRIVATE, "", "nic_id"],

        # Windows v6 bind any doesn't need scope ID.
        ["Windows", IP6, IP_BIND_TUP, V6_VALID_ANY, None, [3, 0]],

        # Localhost V6 bind tups don't need the scope ID.
        ["*", IP6, IP_BIND_TUP, V6_VALID_LOCALHOST, None, [3, 0]],

        # Other private v6 bind tups need the scope id in Windows.
        ["Windows", IP6, IP_BIND_TUP, IP_PRIVATE, None, [3, "nic_id"]],
    ]

def resolve_bind_ip(ip, af, nic_id, plat, bind_magic):
    """
    Processes IP_APPEND rules to normalize the IP string before lookup.
    """
    for bind_rule in bind_magic:
        rule_match = match_bind_rule(ip, af, plat, bind_rule, IP_APPEND)
        if not rule_match:
            continue

        # Do norm rule.
        if rule_match.norm == "":
            pass # Todo: norm IP.
        elif rule_match.norm is not None:
            ip = rule_match.norm

        # Do logic specific to IP_APPEND.
        if rule_match.change is not None:
            if rule_match.change == "nic_id":
                ip += fstr("%{0}", (nic_id,))
            else:
                ip += rule_match.change

        # Only one rule ran per type.
        break
    
    return ip

def resolve_bind_tuple(initial_tup, ip, af, nic_id, plat, bind_magic):
    """
    Processes IP_BIND_TUP rules to modify the tuple (e.g. Scope IDs) after lookup.
    """
    bind_tup = initial_tup

    for bind_rule in bind_magic:
        # Skip rule types we're not processing.
        rule_match = match_bind_rule(ip, af, plat, bind_rule, IP_BIND_TUP)
        if not rule_match:
            continue

        # Apply changes to the bind tuple.
        offset, val_str = rule_match.change
        if val_str == "nic_id":
            val = nic_id
        else:
            val = val_str
            
        bind_tup = list(bind_tup)
        # Check offset range to be safe
        if offset < len(bind_tup):
            bind_tup[offset] = val
            
        bind_tup = tuple(bind_tup)
            
        # Only one rule ran per type.
        break
    
    return bind_tup

# --- Main Functions ---

async def binder_async(af, ip="", port=0, nic_id=None, plat=platform.system()):
    """
    Async version of the binder.
    """
    # 1. Get Rules and Prepare IP
    bind_magic = get_bind_magic_table(af)
    ip = resolve_bind_ip(ip, af, nic_id, plat, bind_magic)

    # 2. Lookup correct bind tuples to use (Async)
    loop = asyncio.get_event_loop()
    try:
        addr_infos = await loop.getaddrinfo(ip, port)
    except Exception:
        addr_infos = []
    
    # Fail gracefully if lookup failed (or handle as per original logic)
    if not addr_infos:
        return None 

    initial_tup = addr_infos[0][4]

    # 3. Finalize Tuple
    return resolve_bind_tuple(initial_tup, ip, af, nic_id, plat, bind_magic)


def binder_sync(af, ip="", port=0, nic_id=None, plat=platform.system()):
    """
    Synchronous version of the binder.
    """
    # 1. Get Rules and Prepare IP
    bind_magic = get_bind_magic_table(af)
    ip = resolve_bind_ip(ip, af, nic_id, plat, bind_magic)

    # 2. Lookup correct bind tuples to use (Sync)
    try:
        addr_infos = socket.getaddrinfo(ip, port)
    except Exception:
        addr_infos = []

    # Fail gracefully if lookup failed (or handle as per original logic)
    if not addr_infos:
        return None

    initial_tup = addr_infos[0][4]

    # 3. Finalize Tuple
    return resolve_bind_tuple(initial_tup, ip, af, nic_id, plat, bind_magic)