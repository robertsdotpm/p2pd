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

from warpgate import Node
from warpgate.node.node_defs import NODE_TEST_CONF, NODE_PORT


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

# TestAutoConnectTurnLive (IPv4 against real TURN infra) — 2600–2699
PORT_TURN_LIVE_A = NODE_PORT + 2600
PORT_TURN_LIVE_B = NODE_PORT + 2601

# Loop tests (run a plugin's happy path 3x against the same node pair) —
# 2700–2799. One block per plugin so each test_loop_<plugin>.py file
# uses its own port pair and they can run in parallel without colliding.
PORT_LOOP_DIRECT_A   = NODE_PORT + 2700; PORT_LOOP_DIRECT_B   = NODE_PORT + 2701
PORT_LOOP_REVERSE_A  = NODE_PORT + 2710; PORT_LOOP_REVERSE_B  = NODE_PORT + 2711
PORT_LOOP_TCP_PUNCH_A = NODE_PORT + 2720; PORT_LOOP_TCP_PUNCH_B = NODE_PORT + 2721
PORT_LOOP_UDP_PUNCH_A = NODE_PORT + 2730; PORT_LOOP_UDP_PUNCH_B = NODE_PORT + 2731
PORT_LOOP_RAND_A     = NODE_PORT + 2740; PORT_LOOP_RAND_B     = NODE_PORT + 2741
PORT_LOOP_TURN_A     = NODE_PORT + 2750; PORT_LOOP_TURN_B     = NODE_PORT + 2751

# How many successive auto_connect runs each loop test fires against the
# same node pair. Bumped from a single-shot to 3 to surface state-leak
# bugs (sockets not closed, plugin slots not freed, MQTT subs not torn
# down, inbound pipe registry not cleared, ...). 3 is enough to expose
# accumulation without making a clean run too slow on slow VMs.
LOOP_COUNT = 3


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
    """Start a node with a pre-built ifs list. ip_list is ignored; the node
    derives its listen IPs from the NICs themselves, matching the demo node."""
    node = Node(ifs=ifs, ip=None, port=port, conf=conf or AUTO_TEST_CONF)
    await asyncio.wait_for(node.start(), timeout=35)
    return node


def isolate_plugins(node, *keep):
    """Pop every plugin from node.traversal.plugin_loaders except keep.

    Tests that assert "plugin X must win the auto_connect race" become
    flaky when any other connection-returning plugin (TURN, random_probe,
    udp_punch, tcp_punch, ...) happens to land its pipe first on a slow
    stack. Whitelisting the plugins under test keeps the assertion
    deterministic and survives new plugins joining the loader without
    requiring every test to update its pop list.
    """
    keep_set = set(keep)
    for name in list(node.traversal.plugin_loaders.keys()):
        if name not in keep_set:
            node.traversal.plugin_loaders.pop(name, None)


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


def pick_listen_ip(nic, af):
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


async def load_two_nodes(test_self, af, label="connectivity"):
    """Load real interfaces and return (nic_a, ip_a, nic_b, ip_b).

    Strictly: probe_ifs[0] -> alice, probe_ifs[1] -> bob. No filtering,
    no reordering. If the machine has fewer than 2 interfaces, or the
    first two interfaces don't both carry an `af` IP, fail (multi-iface
    machine but bad fixture state) or skipTest (single-iface machine).
    """
    if_names = await list_interfaces()
    probe_ifs = await load_interfaces(
        if_names, Interface, min_agree=1, max_agree=4, timeout=4,
    )

    if len(probe_ifs) < 2:
        test_self.skipTest(
            "Need >=2 interfaces (have {0}) for {1}".format(len(probe_ifs), label)
        )

    ip_a = pick_listen_ip(probe_ifs[0], af)
    ip_b = pick_listen_ip(probe_ifs[1], af)
    if not ip_a or not ip_b:
        # AF asymmetry between NICs is environmental (e.g. a mobile carrier
        # NIC that doesn't bring up IPv6). It's not a regression in warpgate, so
        # skip rather than fail.
        test_self.skipTest(
            "probe_ifs[0/1] don't both carry a routable {0} IP "
            "(a={1!r} b={2!r}) for {3}".format(af, ip_a, ip_b, label)
        )
    # Wrap each NIC in a list so callers can pass directly to
    # start_node_with_ifs(ifs=[...], ...).
    return [probe_ifs[0]], ip_a, [probe_ifs[1]], ip_b
