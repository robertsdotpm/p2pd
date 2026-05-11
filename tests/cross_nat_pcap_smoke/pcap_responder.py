"""Cross-platform pcap responder for the cross-NAT pcap smoke test.

Generalisation of xp_responder.py.  Runs ON the responder host
(Linux, macOS, FreeBSD, GhostBSD, or XP-via-the-other-script) and
drives aionetiface's userspace pcap TCP stack (Connection in
simul=True mode) to perform a TCP simul-open against a non-pcap
kernel-TCP peer on p2pd.net.

Why per-OS firewall handling matters
------------------------------------
XP's tcpip.sys RSTs simul-open ~174 ms after the handshake even when
we capture the SYN at NDIS level (documented in CLAUDE.md).  On
Linux/macOS/BSD the kernel doesn't have that specific quirk, but the
generic problem still applies: if the kernel sees the inbound SYN and
nothing is bound to the predicted port, the kernel RSTs.

Solution: on every non-Windows OS, install a transient inbound-TCP
DROP rule for the predicted local port BEFORE the punch fires.  The
pcap stack still sees the SYN at the L2 capture layer; the kernel
just never gets a chance to respond.  Rule is torn down in
finally so a single bad run doesn't leave the host firewalled.

CLI:
    python pcap_responder.py
        --iface             pcap-level iface name (e.g. "ens192" on
                            Linux, "en0" on macOS, "em0" on FreeBSD,
                            \\Device\\NPF_{GUID} on Windows)
        --local-ip          The IP the pcap stack writes as src on
                            outbound frames (NIC's LAN IP)
        --local-port        Local TCP port for the punch
        --remote-ip         Peer's public IP
        --remote-port       Peer's bound source port
        --punch-at          float wall-clock seconds (time.time())
        --timeout           seconds to wait for ESTABLISHED
                            (default 15.0)
        --skip-firewall     skip host firewall manipulation (for
                            debugging; default off)

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


PAYLOAD_A_TO_B = bytes(bytearray((i * 7 + 11) % 251 for i in range(256)))
PAYLOAD_B_TO_A = bytes(bytearray((i * 13 + 5) % 251 for i in range(256)))


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--local-ip", required=True)
    parser.add_argument("--local-port", required=True, type=int)
    parser.add_argument("--remote-ip", required=True)
    parser.add_argument("--remote-port", required=True, type=int)
    parser.add_argument("--punch-at", required=True, type=float)
    parser.add_argument("--timeout", default=20.0, type=float)
    parser.add_argument("--skip-firewall", action="store_true")
    return parser.parse_args()


def validate_port(port):
    if port == 22:
        raise ValueError("port 22 is forbidden for punch tests")
    if port < 2024 or port > 52023:
        raise ValueError(
            "port {0} out of allowed range [2024, 52023]".format(port))


async def responder_coro(args, backend):
    print("pcap_responder: starting; iface={0} local={1}:{2} remote={3}:{4} "
          "punch_at={5} platform={6}".format(
              args.iface, args.local_ip, args.local_port,
              args.remote_ip, args.remote_port,
              args.punch_at, sys.platform))

    from aionetiface.net.pcap import PcapError
    from aionetiface.net.pcap.tcp.conn import Connection, ConnectionError2

    bpf = "tcp and port {0} and port {1}".format(
        args.local_port, args.remote_port)
    try:
        backend.set_filter(bpf)
        print("pcap_responder: BPF filter applied: {0}".format(bpf))
    except PcapError as exc:
        print("pcap_responder: set_filter failed: {0} (continuing)".format(exc))

    now = time.time()
    delay = args.punch_at - now
    if delay > 0:
        print("pcap_responder: sleeping {0:.3f}s until punch_at".format(delay))
        await asyncio.sleep(delay)
    else:
        print("pcap_responder: punch_at already passed by {0:.3f}s; "
              "firing immediately".format(-delay))

    conn = Connection(backend, args.local_ip)
    await conn.start_active(
        remote_ip=args.remote_ip,
        remote_port=args.remote_port,
        local_port=args.local_port,
        simul=True,
    )
    print("pcap_responder: start_active issued; awaiting ESTABLISHED")

    try:
        await conn.wait_established(timeout=args.timeout)
    except ConnectionError2 as exc:
        print("pcap_responder: wait_established raised {0}".format(exc))
        try:
            await conn.close()
        except Exception:
            pass
        return 1
    except asyncio.TimeoutError:
        print("pcap_responder: wait_established timed out after "
              "{0:.1f}s".format(args.timeout))
        try:
            await conn.close()
        except Exception:
            pass
        return 1

    print("pcap_responder: ESTABLISHED at t={0:.3f}".format(time.time()))

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
        print("pcap_responder: A->B payload mismatch got={0} "
              "expected={1}".format(len(rx), len(PAYLOAD_A_TO_B)))
        try:
            await conn.close()
        except Exception:
            pass
        return 1
    print("pcap_responder: received {0} bytes A->B intact".format(len(rx)))

    try:
        await conn.send(PAYLOAD_B_TO_A)
    except Exception as exc:
        print("pcap_responder: send B->A raised {0}".format(exc))
        try:
            await conn.close()
        except Exception:
            pass
        return 1
    print("pcap_responder: sent {0} bytes B->A".format(len(PAYLOAD_B_TO_A)))

    await asyncio.sleep(0.5)

    try:
        await conn.close()
    except Exception:
        pass
    print("pcap_responder: ok")
    return 0


def open_pcap_or_die(iface_name):
    from aionetiface.net.pcap import (
        get_backend, PcapUnavailableError, PcapError,
    )
    try:
        factory = get_backend()
    except PcapUnavailableError as exc:
        print("pcap_responder: pcap unavailable: {0}".format(exc))
        return None
    if not factory.available():
        print("pcap_responder: pcap factory not available")
        return None
    print("pcap_responder: pcap library = {0}".format(
        factory.library_version()))
    try:
        backend = factory.open(iface_name, timeout_ms=10)
    except PcapError as exc:
        print("pcap_responder: pcap_open_live failed: {0}".format(exc))
        return None
    return backend


def main():
    args = parse_args()
    try:
        validate_port(args.local_port)
        validate_port(args.remote_port)
    except ValueError as exc:
        print("pcap_responder: port validation failed: {0}".format(exc))
        return 2

    try:
        from aionetiface.entrypoint import aionetiface_setup_event_loop
        aionetiface_setup_event_loop()
    except ImportError as exc:
        print("pcap_responder: aionetiface bootstrap failed: {0}".format(exc))
        return 2

    # Import host_firewall lazily so an import error doesn't kill the
    # responder before it can log the platform.  This file lives next
    # to pcap_responder.py in the same directory, so plain sys.path
    # injection of __file__'s dir is enough.
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import host_firewall
    except ImportError as exc:
        print("pcap_responder: host_firewall import failed: {0}".format(exc))
        return 2

    backend = open_pcap_or_die(args.iface)
    if backend is None:
        return 2

    installed_firewall = False
    try:
        if not args.skip_firewall:
            try:
                host_firewall.install_block(args.local_port)
                installed_firewall = True
                print("pcap_responder: firewall DROP installed on port {0}".format(
                    args.local_port))
            except Exception as exc:
                print("pcap_responder: firewall install failed: {0}".format(exc))
                try:
                    backend.close()
                except Exception:
                    pass
                return 2
        else:
            print("pcap_responder: --skip-firewall set; not installing rule")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(responder_coro(args, backend))
        finally:
            try:
                loop.close()
            except Exception:
                pass
    finally:
        try:
            backend.close()
        except Exception:
            pass
        if installed_firewall:
            try:
                host_firewall.remove_block(args.local_port)
                print("pcap_responder: firewall DROP removed on port {0}".format(
                    args.local_port))
            except Exception as exc:
                print("pcap_responder: firewall remove failed: {0}".format(exc))


if __name__ == "__main__":
    sys.exit(main())
