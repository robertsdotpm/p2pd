import multiprocessing as mp
import socket
from multiprocessing.reduction import send_handle, recv_handle
import os

def worker(conn):
    s = socket.socket()
    s.connect(("example.com", 80))

    # send FD to parent
    send_handle(conn, s.fileno(), os.getppid())

    # close worker copy
    s.close()

if __name__ == "__main__":
    parent_conn, child_conn = mp.Pipe()

    p = mp.Process(target=worker, args=(child_conn,))
    p.start()

    fd = recv_handle(parent_conn)
    s = socket.socket(fileno=fd)

    s.send(b"GET / HTTP/1.0\r\n\r\n")
    print(s.recv(1024))

    p.join()