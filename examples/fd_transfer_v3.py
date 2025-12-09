import multiprocessing as mp
import socket
import os

def worker(fd):
    s = socket.socket(fileno=fd)
    s.send(b"GET / HTTP/1.0\r\n\r\n")
    print(s.recv(1024))
    s.close()

if __name__ == "__main__":
    # 1. Create the socket in the parent
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("example.com", 80))

    # 2. Make the FD inheritable
    os.set_inheritable(s.fileno(), True)

    # 3. Launch child with *numeric FD*
    p = mp.Process(target=worker, args=(s.fileno(),))
    p.start()

    # parent may optionally close
    s.close()

    p.join()