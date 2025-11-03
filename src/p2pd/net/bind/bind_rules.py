from ...utility.utils import *
from ..net_utils import *
from .bind_utils import *

"""
Returns the correct bind tuple given an af and listen IP.

Designed to support all kinds of common listen addresses
and interface-specific addresses across platforms.
Special attention has been paid to simplifying IPv6 support.

The knowledge within this function has come from testing
many different address types across operating systems
and uses a data-driven table of edge-cases over implementing
edge-case code directly. This greatly simplifies the
original code while improving maintainability.
"""
async def binder(af, ip="", port=0, nic_id=None, loop=None, plat=platform.system()):
    # Table of edge-cases for bind() across platforms and AFs.
    bind_magic = [
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

    # Process IP_APPEND bind rules.
    bind_tup = None
    for bind_rule in bind_magic:
        bind_rule = match_bind_rule(ip, af, plat, bind_rule, IP_APPEND)
        if not bind_rule:
            continue

        # Do norm rule.
        if bind_rule.norm == "":
            pass # Todo: norm IP.
        else:
            if bind_rule.norm is not None:
                ip = bind_rule.norm

        # Do logic specific to IP_APPEND.
        if bind_rule.change is not None:
            if bind_rule.change == "nic_id":
                ip += fstr("%{0}", (nic_id,))
            else:
                ip += bind_rule.change

        # Only one rule ran per type.
        break

    # Lookup correct bind tuples to use.
    loop = loop or asyncio.get_event_loop()
    try:
        addr_infos = await loop.getaddrinfo(ip, port)
    except:
        addr_infos = []

    if not len(addr_infos):
        raise Exception(fstr("Can't resolve {0} for bind.", (ip,)))
    
    # Set initial bind tup.
    bind_tup = addr_infos[0][4]
        
    # Process IP_BIND_TUP if needed.
    for bind_rule in bind_magic:
        # Skip rule types we're not processing.
        bind_rule = match_bind_rule(ip, af, plat, bind_rule, IP_BIND_TUP)
        if not bind_rule:
            continue

        # Apply changes to the bind tuple.
        offset, val_str = bind_rule.change
        if val_str == "nic_id":
            val = nic_id
        else:
            val = val_str
        bind_tup = list(bind_tup)
        bind_tup[offset] = val
        bind_tup = tuple(bind_tup)
            
        # Only one rule ran per type.
        break

    return bind_tup