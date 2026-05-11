"""Driver: tcp_punch_pcap_v2 PunchPcapV2Plugin on the responder side.

Invokes the v2 plugin directly via its actual entry points
(Plugin.run with reply=None first, then reply=PunchMsg as JSON
delivered over stdin). Outbound PunchMsgs are emitted as
JSON lines on stdout, prefixed "SIG:" so the coordinator can
demultiplex from regular log output.

Constraints:
- Python 3.5+ compatible.
- No leading-underscore names.
- Print statements stay; this is observability.

CLI:
    python v2_responder.py
        --iface IFACE
        --local-ip IP
        --remote-ip IP
        --remote-public-ip IP   # the IP the peer claims to bind from
        --plugin-id ID          # shared by both peers
        --bound-port PORT       # specific bind ports our STUN-less
                                #   path returns (test harness)
        --timeout S
"""
import argparse
import asyncio
import json
import os
import socket
import sys
import time
import traceback


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--local-ip", required=True)
    p.add_argument("--remote-ip", required=True)
    p.add_argument("--remote-public-ip", required=True)
    p.add_argument("--plugin-id", required=True)
    p.add_argument("--timeout", default=60.0, type=float)
    return p.parse_args()


def emit_sig(msg_dict):
    """Emit an outbound PunchMsg as a JSON line on stdout."""
    sys.stdout.write("SIG:" + json.dumps(msg_dict) + "\n")
    sys.stdout.flush()


def log_print(text):
    print("v2_responder: " + text, flush=True)


async def make_signal_sender(plugin_id):
    async def send_signal(msg, plugin, relay_no):
        d = msg.to_dict()
        d.setdefault("meta", {})
        d["meta"]["plugin_id"] = plugin_id
        d["meta"]["plugin_name"] = "tcp_punch"
        emit_sig(d)
        return True
    return send_signal


async def stdin_reader_loop(queue):
    """Read JSON lines from stdin; deliver decoded payloads to queue."""
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    while True:
        line = await reader.readline()
        if not line:
            await queue.put(None)
            return
        text = line.decode("utf-8", "replace").strip()
        if not text:
            continue
        if text.startswith("SIG:"):
            try:
                payload = json.loads(text[4:])
            except Exception as exc:
                log_print("stdin JSON decode failed: {0} text={1!r}".format(
                    exc, text))
                continue
            await queue.put(payload)
        else:
            log_print("stdin non-SIG line: {0!r}".format(text))


async def main_coro(args):
    log_print("starting; iface={0} local={1} remote={2}/{3} plugin_id={4}".format(
        args.iface, args.local_ip, args.remote_ip, args.remote_public_ip,
        args.plugin_id))

    # Bootstrap event loop for aionetiface.
    from aionetiface.entrypoint import aionetiface_setup_event_loop
    aionetiface_setup_event_loop()

    from aionetiface import (
        Interface, SysClock, TCP, get_n_stun_clients, RFC5389, USE_MAP_NO,
    )
    from p2pd.traversal.plugins.tcp_punch_pcap_v2 import main as v2_main
    from p2pd.traversal.plugins.tcp_punch.punch_defs import PUNCH_CONF
    from p2pd.traversal.plugins.tcp_punch.proto import PunchMsg

    nic = await Interface(args.iface).start()
    log_print("interface up: {0}".format(nic.name))

    af = socket.AF_INET
    # Use real wall-clock as the NTP seed so both peers agree on
    # absolute bucket boundaries. SysClock(None, 0.1) makes time()
    # start at 0.1 + monotonic_delta, which leaves the two peers'
    # clocks offset by their relative process-start times -- breaks
    # bucket alignment.
    sys_clock = SysClock(None, time.time())
    try:
        loop = asyncio.get_event_loop()
        ntp_clock = sys_clock
        log_print("sys_clock initial time={0:.3f} uncertainty={1}".format(
            sys_clock.time(), getattr(sys_clock, "uncertainty", "?")))
    except Exception as exc:
        log_print("sys_clock init failed: {0}".format(exc))
        return 2

    log_print("loading STUN clients (TCP) for af=v4...")
    try:
        stuns = await asyncio.wait_for(
            get_n_stun_clients(
                af=af, n=USE_MAP_NO, mode=RFC5389,
                interface=nic, proto=TCP, conf=PUNCH_CONF,
            ),
            timeout=20.0,
        )
    except Exception as exc:
        log_print("get_n_stun_clients raised {0}: {1}".format(
            type(exc).__name__, exc))
        traceback.print_exc()
        return 2
    if not stuns:
        log_print("no STUN clients returned; aborting")
        return 2
    log_print("got {0} STUN clients".format(len(stuns)))

    if_index = nic.get_nic_id(af)
    stun_clients_map = {af: {if_index: stuns}}

    # Build the v2 plugin via the factory shape, mimicking what
    # PunchPluginFactory.create produces. v2 doesn't need a proc pool.
    factory = v2_main.PunchPcapV2Factory.create(stun_clients_map, sys_clock)
    plugin = factory.build_plugin()
    plugin.plugin_id = args.plugin_id

    # Provide a NAT info: open NAT (no NAT, fedora is behind one but
    # for this test we assume cone behavior). Empty dict -> NATPredictAlloc
    # falls back to RESTRICT_PORT_NAT + EQUAL_DELTA defaults.
    src = {
        "ip": args.local_ip,
        "if_index": if_index,
        "nat": {},
        "port": 0,
    }
    dest = {
        "ip": args.remote_public_ip,
        "if_index": if_index,
        "nat": {},
        "port": 0,
    }
    plugin.set_addrs({"os": "Linux"}, {"os": "Linux"})
    plugin.set_routing(af, src, dest, nic)
    from aionetiface import EXT_BIND
    plugin.set_context(EXT_BIND, same_machine=False, set_bind=None,
                       timeout=args.timeout)

    queue = asyncio.Queue()
    sender = await make_signal_sender(args.plugin_id)
    plugin.set_send_signal(sender)
    plugin.inbound_pipes = {}

    stdin_task = asyncio.ensure_future(stdin_reader_loop(queue))

    log_print("invoking plugin.run(reply=None)")
    try:
        await plugin.run(reply=None)
    except Exception as exc:
        log_print("plugin.run(initial) raised {0}: {1}".format(
            type(exc).__name__, exc))
        traceback.print_exc()
        stdin_task.cancel()
        return 1

    log_print("initial run returned; awaiting peer signal")

    # Drive subsequent run() calls each time we get a peer reply.
    deadline = time.time() + args.timeout
    while time.time() < deadline and not plugin.result.done():
        remaining = deadline - time.time()
        try:
            payload = await asyncio.wait_for(queue.get(), timeout=min(remaining, 5.0))
        except asyncio.TimeoutError:
            log_print("no peer signal yet; result_done={0}".format(
                plugin.result.done()))
            continue
        if payload is None:
            log_print("stdin closed")
            break
        log_print("got peer signal payload mappings={0}".format(
            len(payload.get("payload", {}).get("mappings", []))))
        reply = PunchMsg(payload)
        try:
            await plugin.run(reply=reply)
        except Exception as exc:
            log_print("plugin.run(reply) raised {0}: {1}".format(
                type(exc).__name__, exc))
            traceback.print_exc()
            break

    log_print("waiting on plugin.result with timeout={0:.1f}s".format(
        deadline - time.time()))
    try:
        winner = await asyncio.wait_for(
            asyncio.shield(plugin.result),
            timeout=max(1.0, deadline - time.time()),
        )
    except asyncio.TimeoutError:
        log_print("plugin.result timed out")
        winner = None
    except Exception as exc:
        log_print("plugin.result raised {0}: {1}".format(
            type(exc).__name__, exc))
        winner = None

    stdin_task.cancel()
    try:
        await stdin_task
    except Exception:
        pass

    log_print("plugin.result winner={0}".format(winner))
    if winner is None:
        return 1

    # Pipe-shim parity exercise: both sides treat the winner as a
    # Pipe-shaped object. v2 receives PING then sends PONG. 1024+ byte
    # payload exercises chunking + the userspace TCP reassembly path.
    exit_code = 0
    try:
        from aionetiface import SUB_ALL
        winner.subscribe(SUB_ALL)
        log_print("subscribed; awaiting legacy PING")
        ping = b""
        deadline_pp = time.time() + 10.0
        while time.time() < deadline_pp:
            chunk = await winner.recv(SUB_ALL, timeout=2)
            if chunk is None:
                continue
            ping += chunk
            if b"-END\n" in ping:
                break
        log_print("recv ping bytes={0} contains_end={1}".format(
            len(ping), b"-END\n" in ping))
        if b"PING-FROM-LEGACY-" not in ping or b"-END\n" not in ping:
            log_print("ping payload mismatch; got first 64={0!r}".format(
                ping[:64]))
            exit_code = 1
        pong = b"PONG-FROM-V2-" + (b"b" * 1000) + b"-END\n"
        sent = await winner.send(pong)
        log_print("sent pong bytes={0}".format(sent))
    except asyncio.CancelledError:
        # 3.8+ split CancelledError out of Exception; handle separately
        # so this branch doesn't swallow loop-shutdown cancellations.
        log_print("payload exchange cancelled")
        exit_code = 1
        raise
    except Exception as exc:
        log_print("payload exchange raised {0}: {1}".format(
            type(exc).__name__, exc))
        traceback.print_exc()
        exit_code = 1
    finally:
        try:
            await winner.close()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log_print("winner.close raised {0}: {1}".format(
                type(exc).__name__, exc))
    return exit_code


def main():
    args = parse_args()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(main_coro(args))
    finally:
        try:
            loop.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
