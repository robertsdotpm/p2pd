import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0)
try:
    s.connect(("192.167.0.1", 33333))
except Exception as e:
    pass
print(s.getsockname())
s.close()