import socket
import selectors
from ..utility.error_logger import *

def selector_proxy(socket_p, destination):
    """
    Bridges an existing connected socket P to a new socket R (connected to destination).
    Supports IPv4 and IPv6 automatically.
    """
    selector = selectors.DefaultSelector()
    
    try:
        # 1. Create the 'Reverse' connection R
        # socket.create_connection automatically handles IPv4 vs IPv6
        socket_r = socket.create_connection(destination, timeout=10)

        # 2. Set both sockets to non-blocking mode
        socket_p.setblocking(False)
        socket_r.setblocking(False)

        # 3. Initialize state
        sockets = [socket_p, socket_r]
        peers = {socket_p: socket_r, socket_r: socket_p}
        buffers = {socket_p: b'', socket_r: b''}

        # 4. Register sockets with the selector for READING initially
        for s in sockets:
            selector.register(s, selectors.EVENT_READ)

        # 5. The Event Loop
        while True:
            # Block until at least one socket is ready
            events = selector.select(timeout=None)

            for key, mask in events:
                sock = key.fileobj
                peer = peers[sock]

                # --- HANDLE READS ---
                if mask & selectors.EVENT_READ:
                    try:
                        data = sock.recv(4096)
                        if data:
                            # If peer wasn't already waiting to write, register it for WRITING
                            if not buffers[peer]:
                                peer_mask = selector.get_key(peer).events
                                selector.modify(peer, peer_mask | selectors.EVENT_WRITE)
                            buffers[peer] += data
                        else:
                            # Empty bytes means connection closed by the other side
                            return
                    except (ConnectionResetError, OSError):
                        return

                # --- HANDLE WRITES ---
                if mask & selectors.EVENT_WRITE:
                    if buffers[sock]:
                        try:
                            sent = sock.send(buffers[sock])
                            buffers[sock] = buffers[sock][sent:]
                            
                            # If buffer is empty, stop watching for WRITE events
                            if not buffers[sock]:
                                current_mask = selector.get_key(sock).events
                                selector.modify(sock, current_mask & ~selectors.EVENT_WRITE)
                        except (BrokenPipeError, OSError):
                            return

    except Exception as e:
        log_exception()

    finally:
        try:
            socket_p.close()
        except: pass
        try:
            if 'socket_r' in locals():
                socket_r.close()
        except: pass
        selector.close()