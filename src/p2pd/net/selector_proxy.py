import selectors
import socket
from ..utility.error_logger import *

def selector_proxy(socket_p, destination):
    """
    Bridges an existing connected socket P to a new socket R (connected to destination).
    Supports IPv4 and IPv6 automatically. Loops forever until both sides close.
    """
    selector = selectors.DefaultSelector()

    try:
        socket_r = socket.create_connection(destination, timeout=10)
        socket_p.setblocking(False)
        socket_r.setblocking(False)

        peers = {socket_p: socket_r, socket_r: socket_p}
        buffers = {socket_p: b'', socket_r: b''}

        for s in peers:
            selector.register(s, selectors.EVENT_READ)

        while peers:
            events = selector.select(timeout=None)
            for key, mask in events:
                sock = key.fileobj
                peer = peers[sock]

                # --- READ ---
                if mask & selectors.EVENT_READ:
                    try:
                        data = sock.recv(4096)
                        if data:
                            buffers[peer] += data
                            selector.modify(peer, selector.get_key(peer).events | selectors.EVENT_WRITE)
                        else:
                            # peer closed, stop reading from this socket
                            selector.unregister(sock)
                            sock.close()
                            del peers[sock]
                            del buffers[sock]
                            continue
                    except (ConnectionResetError, OSError):
                        selector.unregister(sock)
                        sock.close()
                        del peers[sock]
                        del buffers[sock]
                        continue

                # --- WRITE ---
                if mask & selectors.EVENT_WRITE and buffers[sock]:
                    try:
                        sent = sock.send(buffers[sock])
                        buffers[sock] = buffers[sock][sent:]
                        if not buffers[sock]:
                            selector.modify(sock, selector.get_key(sock).events & ~selectors.EVENT_WRITE)
                    except (BrokenPipeError, OSError):
                        selector.unregister(sock)
                        sock.close()
                        del peers[sock]
                        del buffers[sock]

    except Exception:
        # optional logging function
        log_exception()
    finally:
        for s in [socket_p, locals().get('socket_r')]:
            if s:
                try:
                    s.close()
                except Exception: pass

        selector.close()
