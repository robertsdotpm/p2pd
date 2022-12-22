import copy
from http.server import BaseHTTPRequestHandler
from http.client import HTTPResponse
from io import BytesIO
import json
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

class ParseHTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        http_parse_headers(self)

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

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
    p = await pipe_open(route=r, proto=TCP, dest=dest)
    p.subscribe(SUB_ALL)

    buf = http_req_buf(route.af, dest.tup[0], dest.tup[1], path, method=method, payload=payload, headers=headers)
    await p.send(buf, dest.tup)
    out = await p.recv(SUB_ALL)

    if do_close:
        await p.close()
        p = None

    if out is not None:
        out = ParseHTTPResponse(out)
        
    return p, out

# Create a HTTP server response.
# Supports JSON or binary.
def http_res(payload, mime, req, client_tup=None):
    # Support JSON responses.
    if mime == "json":
        # Document content is a JSON string with good indenting.
        payload = json.dumps(payload, indent=4, sort_keys=True)
        payload = to_b(payload)
        content_type = b"application/json"

    # Support binary responses.
    if mime == "binary":
        content_type = b"application/octet-stream"

    # CORS policy header line.
    allow_origin = b"Access-Control-Allow-Origin: %s" % (
        to_b(req.hdrs["Origin"])
    )

    # List of HTTP headers to send for our el8 web server.
    res  = b"HTTP/1.1 200 OK\r\n"
    res += b"%s\r\n" % (allow_origin)
    if client_tup is not None:
        res += b"x-client-tup: %s:%d\r\n" % ( 
            to_b(client_tup[0]),
            client_tup[1]
        )
    else:
        res += b"x-client-tup: unknown\r\n"
    res += b"Content-Type: %s\r\n" % (content_type)
    res += b"Connection: close\r\n"
    res += b"Content-Length: %d\r\n\r\n" % (len(payload))
    res += payload
    
    return res

async def send_json(a_dict, req, client_tup, pipe):
    remote_client_tup = None
    if "client_tup" in a_dict:
        remote_client_tup = a_dict["client_tup"]

    res = http_res(a_dict, "json", req, remote_client_tup)
    await pipe.send(res, client_tup)
    await pipe.close()

async def send_binary(out, req, client_tup, pipe):
    res = http_res(out[1], "binary", req, client_tup=out[0])
    await pipe.send(res, client_tup)
    await pipe.close()