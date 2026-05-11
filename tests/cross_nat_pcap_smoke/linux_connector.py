"""Linux connector for the cross-NAT pcap smoke test.

Runs ON the debian-nat host (a Linux VM, possibly itself behind a
192.168.x.x NAT egressing to a public IPv4).  Drives the LEGACY
kernel-stack tcp_punch helpers -- exactly the path that any non-XP
peer takes in production.  No userspace pcap on this side: real
SOCK_STREAM, real bind, real connect_ex SYN spray.

Wire protocol with the XP peer:
    - Both sides bind their local TCP port (pre-agreed).
    - Both sides fire SYNs at the same wall-clock time (punch_at).
    - We connect to (xp_public_ip, xp_local_port) -- the same port
      the XP peer bound, on the assumption that XP's LAN NAT
      preserves source ports for outbound SYNs (cone NAT).
    - If both NATs cooperate, simul-open completes and the kernel
      reports getpeername success.

CLI:
    python3 linux_connector.py
        --local-ip          NIC IP we bind on (e.g. 192.168.206.2)
        --local-port        Local TCP port to bind for the punch
        --peer-public-ip    XP's public IP (post-NAT)
        --peer-port         The port XP bound (what we connect to)
        --punch-at          float wall-clock seconds (time.time())
        --spray-duration    seconds to keep firing connect_ex
                            (default 3.0)
        --monitor-duration  seconds to wait for ESTABLISHED after
                            spray (default 5.0)
        --timeout           total seconds before giving up (default 15)

Exit codes:
    0   ESTABLISHED + round-trip succeeded
    1   handshake failed / no ESTABLISHED / round-trip mismatch
    2   import / argument error
"""
import argparse
import selectors
import socket as stdlib_socket
import sys
import time


PAYLOAD_A_TO_B = bytes(bytearray((i * 7 + 11) % 251 for i in range(256)))
PAYLOAD_B_TO_A = bytes(bytearray((i * 13 + 5) % 251 for i in range(256)))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-ip", required=True)
    parser.add_argument("--local-port", required=True, type=int)
    parser.add_argument("--peer-public-ip", required=True)
    parser.add_argument("--peer-port", required=True, type=int)
    parser.add_argument("--punch-at", required=True, type=float)
    parser.add_argument("--spray-duration", default=3.0, type=float)
    parser.add_argument("--monitor-duration", default=5.0, type=float)
    parser.add_argument("--timeout", default=15.0, type=float)
    return parser.parse_args()


def validate_port(port):
    if port == 22:
        raise ValueError("port 22 is forbidden for punch tests")
    if port < 2024 or port > 52023:
        raise ValueError(
            "port {0} out of allowed range [2024, 52023]".format(port))


def main():
    args = parse_args()
    try:
        validate_port(args.local_port)
        validate_port(args.peer_port)
    except ValueError as exc:
        print("linux_connector: port validation failed: {0}".format(exc))
        return 2

    print("linux_connector: starting; local={0}:{1} peer={2}:{3} "
          "punch_at={4}".format(
              args.local_ip, args.local_port,
              args.peer_public_ip, args.peer_port,
              args.punch_at))

    # Make the legacy engine importable.  The dispatcher hard-resets
    # /tmp/sweep_repos to pcap_experiment before this script runs.
    sys.path.insert(0, "/tmp/sweep_repos/p2pd/src")
    sys.path.insert(0, "/tmp/sweep_repos/aionetiface/src")

    try:
        from p2pd.traversal.plugins.tcp_punch.tcp_punch_utils import (
            bind_tcp_sockets, connect_on_tcp_sockets,
        )
        from p2pd.traversal.plugins.tcp_punch.tcp_punch_engine import (
            socket_event_monitor,
        )
        from p2pd.traversal.plugins.tcp_punch.punch_defs import PortAlloc
    except ImportError as exc:
        print("linux_connector: import failed: {0}".format(exc))
        return 2

    # One src/dest pair: this is a smoke test, not a NUM_PORTS-wide
    # spray.  The legacy engine accepts any number of PortAlloc; we
    # keep it deterministic so the result is interpretable.
    allocs = [PortAlloc(args.local_port, args.peer_port)]

    try:
        bound = bind_tcp_sockets(
            af=stdlib_socket.AF_INET,
            nic_id=None,
            port_allocs=allocs,
            src_ip=args.local_ip,
            route=None,
        )
    except OSError as exc:
        print("linux_connector: bind_tcp_sockets raised {0}".format(exc))
        return 1
    if not bound:
        print("linux_connector: bind_tcp_sockets returned empty list")
        return 1
    print("linux_connector: bound {0} socket(s)".format(len(bound)))

    sel = selectors.DefaultSelector()
    for pa, s in bound:
        s.setblocking(False)
        sel.register(s, selectors.EVENT_WRITE | selectors.EVENT_READ)

    # Sleep until wall-clock punch time, MINUS a lead time so this
    # side enters connect_ex spray ~LEAD_TIME_S BEFORE the peer's SYN
    # is expected to land.  Without the lead, both sides target the
    # same instant and clock-probe residual error (observed ~150 ms
    # with a 3 s SSH RTT) is enough for the peer's SYN to arrive
    # before this side has a socket in SYN_SENT -- kernel sees an
    # unsolicited SYN to a closed/listening port and RSTs.  By
    # starting the spray early, the local socket is already in
    # SYN_SENT when the peer's SYN lands and the kernel treats the
    # exchange as simul-open, completing the handshake.
    #
    # connect_on_tcp_sockets sprays for spray_duration seconds (we
    # pass 3.0), so a 0.5s lead leaves ~2.5s of spray AFTER the
    # nominal punch_at -- plenty of overlap with the peer's own
    # spray window.
    LEAD_TIME_S = 0.5
    now = time.time()
    delay = args.punch_at - LEAD_TIME_S - now
    if delay > 0:
        print("linux_connector: sleeping {0:.3f}s until punch_at-{1:.3f}s "
              "(lead time)".format(delay, LEAD_TIME_S))
        time.sleep(delay)
    else:
        print("linux_connector: punch_at-lead already passed by {0:.3f}s; "
              "firing immediately".format(-delay))

    # Spray SYNs at the peer.  same_machine=False since we're
    # cross-NAT WAN -- we want the engine's normal RTT slack.
    print("linux_connector: spraying SYNs to {0}:{1} for {2:.2f}s".format(
        args.peer_public_ip, args.peer_port, args.spray_duration))
    try:
        connect_on_tcp_sockets(
            same_machine=False, bound_infos=bound,
            dest_ip=args.peer_public_ip,
            spray_duration=args.spray_duration,
        )
    except Exception as exc:
        print("linux_connector: connect_on_tcp_sockets raised {0}".format(exc))
        sel.close()
        for pa, s in bound:
            try:
                s.close()
            except OSError:
                pass
        return 1

    print("linux_connector: monitoring sockets for ESTABLISHED")
    try:
        successful = socket_event_monitor(
            sel, monitor_duration=args.monitor_duration,
            retry_interval=0.05,
        )
    except Exception as exc:
        print("linux_connector: socket_event_monitor raised {0}".format(exc))
        sel.close()
        for pa, s in bound:
            try:
                s.close()
            except OSError:
                pass
        return 1

    winning_sock = None
    for pa, s in bound:
        if s in successful and winning_sock is None:
            winning_sock = s
        else:
            try:
                s.close()
            except OSError:
                pass
    sel.close()

    if winning_sock is None:
        print("linux_connector: no ESTABLISHED sockets after monitor; "
              "punch failed")
        return 1

    try:
        peer = winning_sock.getpeername()
    except OSError as exc:
        print("linux_connector: getpeername raised {0}".format(exc))
        try:
            winning_sock.close()
        except OSError:
            pass
        return 1
    print("linux_connector: ESTABLISHED at t={0:.3f}, peer={1}".format(
        time.time(), peer))

    # Confirm we landed on the right peer.  Note: the peer addr the
    # kernel reports is the post-NAT public IP of XP, not its LAN IP.
    if peer[0] != args.peer_public_ip:
        print("linux_connector: peer IP {0} != expected {1}".format(
            peer[0], args.peer_public_ip))
        try:
            winning_sock.close()
        except OSError:
            pass
        return 1

    # Round-trip: connector sends first, then reads echo.
    winning_sock.setblocking(True)
    winning_sock.settimeout(10.0)
    try:
        winning_sock.sendall(PAYLOAD_A_TO_B)
    except OSError as exc:
        print("linux_connector: sendall A->B raised {0}".format(exc))
        try:
            winning_sock.close()
        except OSError:
            pass
        return 1
    print("linux_connector: sent {0} bytes A->B".format(len(PAYLOAD_A_TO_B)))

    rx = bytearray()
    deadline = time.time() + 10.0
    while len(rx) < len(PAYLOAD_B_TO_A) and time.time() < deadline:
        try:
            chunk = winning_sock.recv(2048)
        except OSError as exc:
            print("linux_connector: recv B->A raised {0}".format(exc))
            try:
                winning_sock.close()
            except OSError:
                pass
            return 1
        if not chunk:
            break
        rx.extend(chunk)

    if bytes(rx) != PAYLOAD_B_TO_A:
        print("linux_connector: B->A payload mismatch got={0} "
              "expected={1}".format(len(rx), len(PAYLOAD_B_TO_A)))
        try:
            winning_sock.close()
        except OSError:
            pass
        return 1
    print("linux_connector: received {0} bytes B->A intact".format(len(rx)))

    try:
        winning_sock.close()
    except OSError:
        pass
    print("linux_connector: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
