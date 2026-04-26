"""
Shared helpers for the test_auto_connect.* split test files.

The original test_auto_connect.py grew six AsyncTestCase classes that all
spin up real nodes and use MQTT/auto_connect. Run together they accumulated
MQTT client / dispatcher / socket state across tests. The runner runs each
test_*.py file in its own subprocess, so each class now lives in its own
file and gets a fresh process. These helpers live here so the split files
do not duplicate them.

Ports: each class reserves a 100-port slot under NODE_PORT + 2000 so the
runner can schedule split files in parallel without colliding.
"""

import asyncio
import copy

from aionetiface import (
    IP4, IP6, IPRange, Interface, DUEL_STACK,
    dict_child, list_interfaces, load_interfaces, sort_ips_by_nic,
)

from p2pd import Node
from p2pd.node.node_defs import NODE_TEST_CONF, NODE_PORT


AUTO_TEST_CONF = dict_child(
    {
        "enable_upnp": False,
        "sig_pipe_no": 1,
        "init_clock_skew": False,
        "enable_punching": False,
        "enable_nickname": False,
        "enable_stun_clients": False,
    },
    NODE_TEST_CONF,
)

# Punch requires STUN clients for NTP timing and port allocation.
PUNCH_TEST_CONF = dict_child(
    {
        "enable_upnp": False,
        "sig_pipe_no": 1,
        "init_clock_skew": False,
        "enable_punching": True,
        "enable_nickname": False,
        "enable_stun_clients": True,
    },
    NODE_TEST_CONF,
)

# Per-class port slots (each class is now its own subprocess but the same
# layout works — and keeps these constants stable).

# TestAutoConnectIPv4 — 2000–2099
PORT_A_T1 = NODE_PORT + 2000; PORT_B_T1 = NODE_PORT + 2001
PORT_A_T2 = NODE_PORT + 2010; PORT_B_T2 = NODE_PORT + 2011
PORT_A_T3 = NODE_PORT + 2020; PORT_B_T3 = NODE_PORT + 2021

# TestAutoConnectIPv6 — 2100–2199
PORT_A6_T1 = NODE_PORT + 2100; PORT_B6_T1 = NODE_PORT + 2101
PORT_A6_T2 = NODE_PORT + 2110; PORT_B6_T2 = NODE_PORT + 2111

# TestAutoConnectReverseConnect — 2200–2299 (single test)
PORT_REV_A = NODE_PORT + 2200; PORT_REV_B = NODE_PORT + 2201

# TestAutoConnectMultiInterface — 2300–2399
PORT_MULTI_A_T1 = NODE_PORT + 2300
PORT_MULTI_A_T2 = NODE_PORT + 2310
PORT_MULTI_A_T3 = NODE_PORT + 2320; PORT_MULTI_B_T3 = NODE_PORT + 2321
PORT_MULTI_A_T4 = NODE_PORT + 2330; PORT_MULTI_B_T4 = NODE_PORT + 2331

# TestAutoConnectPunch — 2400–2499
PORT_PUNCH_A_T1 = NODE_PORT + 2400; PORT_PUNCH_B_T1 = NODE_PORT + 2401
PORT_PUNCH_A_T2 = NODE_PORT + 2410; PORT_PUNCH_B_T2 = NODE_PORT + 2411

# TestAutoConnectTurnFallback — 2500–2599
PORT_TURN_A_T1 = NODE_PORT + 2500; PORT_TURN_B_T1 = NODE_PORT + 2501
PORT_TURN_A_T2 = NODE_PORT + 2510
PORT_TURN_A_T3 = NODE_PORT + 2520; PORT_TURN_B_T3 = NODE_PORT + 2521


def clone_nic(real_nic, new_id, ip_list):
    """Return a shallow copy of real_nic with a different id and a filtered route pool.

    The copy keeps real_nic.name so that IPv6 scope-ID appending still uses the
    correct physical interface name. new_id makes sort_ips_by_nic treat this as
    a distinct interface from real_nic, enabling multi-interface node setups on a
    single physical NIC.

    ip_list must be a list of IP address strings. Only address families present
    in ip_list are kept in the route pool; the rest are cleared so this clone only
    claims those specific addresses.
    """
    from aionetiface.nic.route.rp_from_ip import route_pool_from_ips
    from aionetiface.nic.route.route_pool import RoutePool

    nic = copy.copy(real_nic)
    nic.id = new_id

    rp = route_pool_from_ips(ip_list, real_nic)

    represented_afs = set()
    for ip in ip_list:
        try:
            represented_afs.add(IPRange(ip).af)
        except Exception:
            pass

    for af in (IP4, IP6):
        if af not in represented_afs:
            rp[af] = RoutePool()

    nic.rp = rp

    # Set stack to match only the AFs that have routes, so nic.supported()
    # doesn't claim IPv6 when only IPv4 addresses were requested (which would
    # cause node startup to call nic.route(IP6) on an empty route pool).
    if len(represented_afs) == 1:
        nic.stack = list(represented_afs)[0]
    else:
        nic.stack = DUEL_STACK

    return nic


async def fresh_ifs():
    """Load a fresh set of interfaces (without NAT detection) for one node."""
    if_names = await list_interfaces()
    return await load_interfaces(if_names, Interface, skip_nat=True)


async def start_node(ip, port, conf=None):
    """Start a node bound to a single IP on freshly loaded interfaces."""
    ifs = await fresh_ifs()
    node = Node(ifs=ifs, ip=[ip], port=port, conf=conf or AUTO_TEST_CONF)
    await asyncio.wait_for(node.start(), timeout=35)
    return node


async def start_node_with_ifs(ifs, ip_list, port, conf=None):
    """Start a node with a pre-built ifs list and explicit listen-IP list."""
    node = Node(ifs=ifs, ip=ip_list, port=port, conf=conf or AUTO_TEST_CONF)
    await asyncio.wait_for(node.start(), timeout=35)
    return node


def ifs_have_ip(ifs, ip_str):
    """Return True if ip_str appears in any NIC's route pool (primary or secondary)."""
    by_nic = sort_ips_by_nic([ip_str], ifs)
    return any(ips for ips in by_nic.values())


def global_ipv6_addrs(ifs):
    """Return unique global (non-link-local, non-loopback) IPv6 strings from all NICs."""
    seen = set()
    addrs = []
    for nic in ifs:
        if IP6 not in nic.supported():
            continue
        for route in nic.rp[IP6]:
            for ipr in route.nic_ips:
                s = str(ipr)
                if s.startswith("fe80") or s in ("::1", "::"):
                    continue
                if s not in seen:
                    seen.add(s)
                    addrs.append(s)
    return addrs


def available_ipv4_addrs(ifs):
    """Return unique non-loopback IPv4 strings from all NICs, ordered by NIC then IP."""
    seen = set()
    addrs = []
    for nic in ifs:
        if IP4 not in nic.supported():
            continue
        for route in nic.rp[IP4]:
            for ipr in route.nic_ips:
                s = str(ipr)
                if s.startswith("127."):
                    continue
                if s not in seen:
                    seen.add(s)
                    addrs.append(s)
    return addrs


async def close_nodes(*nodes):
    for node in nodes:
        if node is not None:
            try:
                await asyncio.wait_for(node.close(), timeout=10)
            except Exception:
                pass


def routable_ips_per_nic(ifs, af):
    """Return [(nic, [ip, ip, ...]), ...] for NICs that hold at least one
    non-loopback address in family `af`.

    For IPv6 we keep link-local (fe80::/10) addresses -- they are valid
    distinct local IPs on different NICs and the demo CLI explicitly uses
    them via `--ip fe80:...` for testing direct_connect with no public
    routing required. Only true loopback (::1 / ::) is filtered.

    The IP order is stable (dedup-preserving order of appearance).
    """
    result = []
    for nic in ifs:
        if af not in nic.supported():
            continue
        try:
            rp = nic.rp[af]
        except (KeyError, AttributeError):
            continue
        seen = set()
        ips = []
        for route in rp:
            for ipr in route.nic_ips:
                s = str(ipr)
                if af == IP4 and s.startswith("127."):
                    continue
                if af == IP6 and s in ("::1", "::"):
                    continue
                if s in seen:
                    continue
                seen.add(s)
                ips.append(s)
        if ips:
            result.append((nic, ips))
    return result


def first_routable_ip(nic, af):
    """Return the first non-loopback `af` IP on nic, or None."""
    if af not in nic.supported():
        return None
    try:
        rp = nic.rp[af]
    except (KeyError, AttributeError):
        return None
    for route in rp:
        for ipr in route.nic_ips:
            s = str(ipr)
            if af == IP4 and s.startswith("127."):
                continue
            if af == IP6 and s in ("::1", "::"):
                continue
            return s
    return None


def split_two_node_setups(probe_ifs, af):
    """Each node gets its own real interface from load_interfaces().

    probe_ifs[0] -> alice, probe_ifs[1] -> bob. No cloning, no loopback
    aliases -- just hand each node a real NIC. apply_listen_ips finds
    the IP because the NIC really owns it.

    Falls back to "single NIC with two distinct IPs" only when only one
    NIC is available (covers single-NIC + IPv6-with-link-local-and-global
    scenarios).

    Returns ((ifs_a, ip_a), (ifs_b, ip_b)) or None.
    """
    # Two real NICs: alice on probe_ifs[0], bob on probe_ifs[1].
    if len(probe_ifs) >= 2:
        ip_a = first_routable_ip(probe_ifs[0], af)
        ip_b = first_routable_ip(probe_ifs[1], af)
        if ip_a and ip_b:
            return (([probe_ifs[0]], ip_a), ([probe_ifs[1]], ip_b))

    # Fallback: single NIC with multiple distinct IPs (rare for IPv4,
    # common for IPv6 link-local + global). Share the NIC reference.
    per_nic = routable_ips_per_nic(probe_ifs, af)
    if len(per_nic) == 1:
        nic, ips = per_nic[0]
        if len(ips) >= 2:
            return (([nic], ips[0]), ([nic], ips[1]))

    return None


def require_split_or_fail(test_self, probe_ifs, af, label="connectivity"):
    """Return (ifs_a, ip_a, ifs_b, ip_b) or skipTest / fail.

    Strict: if 2+ NICs are present, the connectivity test MUST run. None
    in that case is treated as a real bug (the test should fail, not
    skip silently). Skip cleanly only when the machine truly lacks the
    interfaces a connectivity test needs.
    """
    setups = split_two_node_setups(probe_ifs, af)
    if setups is None:
        if len(probe_ifs) >= 2:
            test_self.fail(
                "Test environment has {0} interfaces but split_two_node_setups "
                "produced no viable {1} setup for {2}".format(
                    len(probe_ifs), af, label,
                )
            )
        test_self.skipTest(
            "Need >=2 NICs (have {0}) for {1}".format(len(probe_ifs), label)
        )
    (ifs_a, ip_a), (ifs_b, ip_b) = setups
    return ifs_a, ip_a, ifs_b, ip_b
