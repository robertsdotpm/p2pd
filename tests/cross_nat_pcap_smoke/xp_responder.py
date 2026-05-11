"""XP responder for the cross-NAT pcap smoke test.

Runs ON the Windows XP host.  Drives aionetiface's userspace pcap TCP
stack (Connection in simul=True mode) so it can perform the simul-open
without involving XP's tcpip.sys -- the documented XP cross-NAT RST
path is what this whole test exists to dodge.

Wire protocol with the Linux peer:
    - Both sides bind a known local TCP port (pre-agreed by the
      coordinator, in [2024, 52023]).
    - Both sides fire SYNs at the same wall-clock time (punch_at).
    - XP's outbound SYN creates / refreshes the LAN NAT mapping for
      its bound source port.  As long as the NAT preserves source
      ports (cone NAT), the Linux side's SYN to
      (xp_public_ip, predicted_port) lands on the same mapping.
    - aionetiface's pcap state machine captures the inbound SYN
      before tcpip.sys can RST it, completes the handshake in
      userspace, returns a Connection.

CLI:
    python xp_responder.py
        --local-ip          XP's LAN IP (the IP behind the NAT,
                            e.g. 10.0.1.132)
        --local-port        Local TCP port to bind for the punch
                            (must equal what the coordinator told
                            the Linux side to expect post-NAT)
        --peer-public-ip    The Linux peer's public IP (the
                            destination XP sends its outbound SYN
                            to; reply arrives from the same address
                            after Linux-side NAT rewrite)
        --peer-port         The Linux peer's bound source port
        --punch-at          float wall-clock seconds (time.time()
                            scale) at which to fire the simul-open
        --iface-pcap-name   Windows pcap device name
                            (\\Device\\NPF_{GUID}); look up via
                            aionetiface.net.pcap.get_backend()
                            list_interfaces()
        --timeout           seconds to wait for ESTABLISHED
                            (default 15.0)

Exit codes:
    0   ESTABLISHED + round-trip succeeded
    1   handshake failed / RST / timeout
    2   import / pcap / argument error
"""
import argparse
import asyncio
import os
import sys
import time


# Echo payloads -- mirror the kernel-TCP side.  Initiator (Linux)
# sends PAYLOAD_A first, responder (XP) echoes PAYLOAD_B back.
PAYLOAD_A_TO_B = bytes(bytearray((i * 7 + 11) % 251 for i in range(256)))
PAYLOAD_B_TO_A = bytes(bytearray((i * 13 + 5) % 251 for i in range(256)))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-ip", required=True)
    parser.add_argument("--local-port", required=True, type=int)
    parser.add_argument("--peer-public-ip", required=True)
    parser.add_argument("--peer-port", required=True, type=int)
    parser.add_argument("--punch-at", required=True, type=float)
    parser.add_argument("--iface-pcap-name", required=True)
    parser.add_argument("--timeout", default=15.0, type=float)
    return parser.parse_args()


def validate_port(port):
    """Hard rule from the dispatcher: punched ports in [2024, 52023]
    and never 22.  Reject loudly so a bad invocation can't silently
    skate past it.
    """
    if port == 22:
        raise ValueError("port 22 is forbidden for punch tests")
    if port < 2024 or port > 52023:
        raise ValueError(
            "port {0} out of allowed range [2024, 52023]".format(port))


async def responder_coro(args):
    print("xp_responder: starting; local={0}:{1} peer={2}:{3} "
          "punch_at={4} iface={5}".format(
              args.local_ip, args.local_port,
              args.peer_public_ip, args.peer_port,
              args.punch_at, args.iface_pcap_name))

    from aionetiface.net.pcap import (
        get_backend, PcapUnavailableError, PcapError,
    )
    from aionetiface.net.pcap.tcp.conn import Connection, ConnectionError2

    try:
        factory = get_backend()
    except PcapUnavailableError as exc:
        print("xp_responder: pcap unavailable: {0}".format(exc))
        return 2
    if not factory.available():
        print("xp_responder: pcap factory not available")
        return 2

    print("xp_responder: pcap library = {0}".format(factory.library_version()))

    try:
        backend = factory.open(args.iface_pcap_name, timeout_ms=10)
    except PcapError as exc:
        print("xp_responder: pcap_open_live failed: {0}".format(exc))
        return 2

    try:
        # Tight BPF: only the two ports we care about.  Reader
        # thread is otherwise drowned by general XP traffic.
        bpf = "tcp and port {0} and port {1}".format(
            args.local_port, args.peer_port)
        try:
            backend.set_filter(bpf)
            print("xp_responder: BPF filter applied: {0}".format(bpf))
        except PcapError as exc:
            print("xp_responder: set_filter failed: {0} (continuing)".format(exc))

        # Wait until wall-clock punch time.  Use absolute time.time()
        # because the coordinator computes it from time.time().
        now = time.time()
        delay = args.punch_at - now
        if delay > 0:
            print("xp_responder: sleeping {0:.3f}s until punch_at".format(delay))
            await asyncio.sleep(delay)
        else:
            print("xp_responder: punch_at already passed by {0:.3f}s; "
                  "firing immediately".format(-delay))

        # Drive the userspace simul-open.  The Connection takes our
        # NIC-local IP (10.0.1.132); the userspace stack writes that
        # as the source on outbound frames.  The LAN NAT rewrites it
        # to 113.29.240.148 on the way out.
        conn = Connection(backend, args.local_ip)
        await conn.start_active(
            remote_ip=args.peer_public_ip,
            remote_port=args.peer_port,
            local_port=args.local_port,
            simul=True,
        )
        print("xp_responder: start_active issued; awaiting ESTABLISHED")

        try:
            await conn.wait_established(timeout=args.timeout)
        except ConnectionError2 as exc:
            print("xp_responder: wait_established raised {0}".format(exc))
            try:
                await conn.close()
            except Exception:
                pass
            return 1
        except asyncio.TimeoutError:
            print("xp_responder: wait_established timed out after "
                  "{0:.1f}s".format(args.timeout))
            try:
                await conn.close()
            except Exception:
                pass
            return 1

        print("xp_responder: ESTABLISHED at t={0:.3f}".format(time.time()))

        # Round-trip.  Wait for PAYLOAD_A_TO_B, then send PAYLOAD_B_TO_A.
        rx = bytearray()
        deadline = asyncio.get_event_loop().time() + 8.0
        while len(rx) < len(PAYLOAD_A_TO_B):
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await conn.recv(2048, timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            rx.extend(chunk)

        if bytes(rx) != PAYLOAD_A_TO_B:
            print("xp_responder: A->B payload mismatch got={0} "
                  "expected={1}".format(len(rx), len(PAYLOAD_A_TO_B)))
            try:
                await conn.close()
            except Exception:
                pass
            return 1
        print("xp_responder: received {0} bytes A->B intact".format(len(rx)))

        try:
            await conn.send(PAYLOAD_B_TO_A)
        except Exception as exc:
            print("xp_responder: send B->A raised {0}".format(exc))
            try:
                await conn.close()
            except Exception:
                pass
            return 1
        print("xp_responder: sent {0} bytes B->A".format(len(PAYLOAD_B_TO_A)))

        # Drain briefly so any final ACKs land before close.
        await asyncio.sleep(0.5)

        try:
            await conn.close()
        except Exception:
            pass
        print("xp_responder: ok")
        return 0
    finally:
        try:
            backend.close()
        except Exception:
            pass


def main():
    args = parse_args()
    try:
        validate_port(args.local_port)
        validate_port(args.peer_port)
    except ValueError as exc:
        print("xp_responder: port validation failed: {0}".format(exc))
        return 2

    # Standard aionetiface bootstrap: install CustomEventLoop policy
    # before creating the loop so the proxy selector is in place.
    try:
        from aionetiface.entrypoint import aionetiface_setup_event_loop
        aionetiface_setup_event_loop()
    except ImportError as exc:
        print("xp_responder: aionetiface bootstrap failed: {0}".format(exc))
        return 2

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(responder_coro(args))
    finally:
        try:
            loop.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
