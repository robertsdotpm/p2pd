"""Driver: legacy tcp_punch.PunchPlugin on the connector side.

Invokes the kernel-socket tcp_punch plugin directly via Plugin.run.
Sees the v2 peer's PunchMsgs (delivered as JSON on stdin), exchanges
its own (emitted as JSON on stdout). Goes through the actual
plugin entry points -- the SYN spray is the real
tcp_selector_punch_engine via punching_process in a thread executor.

Same wire as v2_responder.py.

CLI:
    python legacy_connector.py
        --iface IFACE
        --local-ip IP
        --remote-ip IP          # peer's bound IP (already public)
        --plugin-id ID
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
    p.add_argument("--plugin-id", required=True)
    p.add_argument("--timeout", default=60.0, type=float)
    return p.parse_args()


def emit_sig(msg_dict):
    sys.stdout.write("SIG:" + json.dumps(msg_dict) + "\n")
    sys.stdout.flush()


def log_print(text):
    print("legacy_connector: " + text, flush=True)


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
    log_print("starting; iface={0} local={1} remote={2} plugin_id={3}".format(
        args.iface, args.local_ip, args.remote_ip, args.plugin_id))

    from aionetiface.entrypoint import aionetiface_setup_event_loop
    aionetiface_setup_event_loop()

    from aionetiface import (
        Interface, SysClock, TCP, get_n_stun_clients, RFC5389, USE_MAP_NO,
    )
    from p2pd.traversal.plugins.tcp_punch import main as legacy_main
    from p2pd.traversal.plugins.tcp_punch.punch_defs import PUNCH_CONF
    from p2pd.traversal.plugins.tcp_punch.proto import PunchMsg

    nic = await Interface(args.iface).start()
    log_print("interface up: {0}".format(nic.name))

    af = socket.AF_INET
    # Use real wall-clock as the NTP seed so both peers agree on
    # absolute bucket boundaries.
    sys_clock = SysClock(None, time.time())
    log_print("sys_clock initial time={0:.3f}".format(sys_clock.time()))

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

    factory = await legacy_main.PunchPluginFactory.create(
        stun_clients_map, sys_clock,
    )
    plugin = factory.build_plugin()
    plugin.plugin_id = args.plugin_id

    # stop_reader for selector_proxy plumbing. Never written to;
    # selector_proxy stops on TCP close.
    stop_rw = socket.socketpair()
    stop_rw[0].setblocking(False)
    plugin.stop_reader = stop_rw[0]

    src = {
        "ip": args.local_ip,
        "if_index": if_index,
        "nat": {},
        "port": 0,
    }
    dest = {
        "ip": args.remote_ip,
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

    # As the connector, the legacy peer normally INITIATES the
    # exchange (first call with reply=None emits the empty trigger
    # PunchMsg; v2 side is RECEIVED_PREDICTIONS first round).
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

    log_print("waiting on plugin.result remaining={0:.1f}s".format(
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
    except asyncio.CancelledError:
        # 3.8+: CancelledError is not an Exception subclass; broad
        # Exception catch lets it escape. Handle as expected outcome.
        pass
    except Exception:
        pass

    log_print("plugin.result winner={0}".format(winner))
    if winner is None:
        return 1

    # Pipe-shim parity exercise: legacy sends PING, awaits v2 PONG.
    # Identical shape to v2_responder.py; both sides duck-type on Pipe.
    exit_code = 0
    try:
        from aionetiface import SUB_ALL
        winner.subscribe(SUB_ALL)
        ping = b"PING-FROM-LEGACY-" + (b"a" * 1000) + b"-END\n"
        sent = await winner.send(ping)
        log_print("sent ping bytes={0}".format(sent))
        log_print("awaiting v2 PONG")
        pong = b""
        deadline_pp = time.time() + 10.0
        while time.time() < deadline_pp:
            chunk = await winner.recv(SUB_ALL, timeout=2)
            if chunk is None:
                continue
            pong += chunk
            if b"-END\n" in pong:
                break
        log_print("recv pong bytes={0} contains_end={1}".format(
            len(pong), b"-END\n" in pong))
        if b"PONG-FROM-V2-" not in pong or b"-END\n" not in pong:
            log_print("pong payload mismatch; got first 64={0!r}".format(
                pong[:64]))
            exit_code = 1
    except asyncio.CancelledError:
        # 3.8+ split: separate handler so loop-shutdown cancellations
        # don't get swallowed by the broad Exception arm below.
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
