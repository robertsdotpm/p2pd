import multiprocessing as mp
import socket
import os
from multiprocessing.reduction import send_handle, recv_handle

# Worker function must now send the *shared handle data*
def worker(conn):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 1. Connect the socket first
        s.connect(("example.com", 80))

        # 2. Get the shareable handle information (bytes)
        # This is a Windows-specific mechanism that works cross-platform.
        shared_data = s.share(os.getppid())

        # 3. Send the raw bytes over the multiprocessing Pipe
        conn.send(shared_data)

        # Close worker copy
        s.close()
    except Exception as e:
        print(f"Worker Error: {e}")

if __name__ == "__main__":
    # Ensure this is run inside the __main__ block for multiprocessing to work
    parent_conn, child_conn = mp.Pipe()

    p = mp.Process(target=worker, args=(child_conn,))
    p.start()

    # Receive the raw bytes (shared data)
    shared_data = parent_conn.recv()

    # Recreate the socket from the shared data
    s = socket.socket().fromshare(shared_data)
    
    # Use the recreated socket
    s.send(b"GET / HTTP/1.0\r\n\r\n")
    print(s.recv(1024))
    
    s.close()
    p.join()