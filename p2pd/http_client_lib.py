import copy
from http.client import HTTPResponse
from .net import *
from .base_stream import *

HTTP_HEADERS = [
    [b"User-Agent", b"curl/7.54.0"],
    [b"Origin", b"null"],
    [b"Accept", b"*/*"]
]

def http_req_buf(af, host, port, path=b"/", method=b"GET", payload=None, headers=None):
    # Format headers.
    hdrs = {}
    if headers is None:
        headers = HTTP_HEADERS
    else:
        headers += HTTP_HEADERS

    # Raw http request.
    buf  = b"%s %s HTTP/1.1\r\n" % (to_b(method), to_b(path))
    if af == IP4:
        host = to_b(host)
    else:
        host = to_b(f"[{to_s(host)}]")
    buf += b"Host: %s:%d\r\n" % (host, port)
    for header in headers:
        n, v = header
        if n not in hdrs:
            buf += b"%s: %s\r\n" % (n, v)
            hdrs[n] = 1
    
    # Terminate request.
    buf += b"\r\n\r\n"
    if payload is not None:
        buf += to_b(payload)

    return buf

def http_parse_headers(self):
    # Get headers from named pair list.
    hdrs = {}
    for named_pair in self.headers._headers:
        name, value = named_pair
        hdrs[name] = value
        hdrs[name.lower()] = value

    # Set origin.
    if 'Origin' not in hdrs:
        hdrs['Origin'] = 'null'
        hdrs['origin'] = 'null'

    # Save header list.
    self.hdrs = hdrs

class ParseHTTPResponse(HTTPResponse):
    def __init__(self, resp_text):
        self.resp_len = len(resp_text)
        self.sock = FakeSocket(resp_text)
        super().__init__(self.sock)
        self.begin()
        http_parse_headers(self)

    def out(self):
        return self.read(self.resp_len)

async def http_req(route, dest, path, do_close=1, method=b"GET", payload=None, headers=None):
    # Get a new con 
    r = copy.deepcopy(route)
    r = await r.bind()
    
    assert(dest is not None)
    log(f"{route} {dest}")
    try:
        p = await pipe_open(route=r, proto=TCP, dest=dest)
    except Exception:
        log_exception()

    if p is None:
        return None, None

    try:
        p.subscribe(SUB_ALL)
        buf = http_req_buf(route.af, dest.tup[0], dest.tup[1], path, method=method, payload=payload, headers=headers)
        await p.send(buf, dest.tup)
        out = await p.recv(SUB_ALL)
    except Exception:
        log_exception()
        await p.close()
        return None, None

    if do_close:
        await p.close()
        p = None

    if out is not None:
        out = ParseHTTPResponse(out)
        
    return p, out