import copy
from http.client import HTTPResponse
from .net import *
from .base_stream import *
from .address import *

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
    # Very important: 1.0 is used to disable 'chunked encoding.'
    # Chunked encoding overly complicates processing HTTP responses.
    buf  = b"%s %s HTTP/1.0\r\n" % (to_b(method), to_b(path))
    if af == IP4:
        host = to_b(host)
    else:
        host = to_b(f"[{to_s(host)}]")
    buf += b"Host: %s\r\n" % (host)
    for header in headers:
        n, v = header

        # Don't add host header twice.
        if n.lower() == b"host":
            continue
        
        # Skip duplicate headers.
        if n not in hdrs:
            buf += b"%s: %s\r\n" % (n, v)
            hdrs[n] = 1

    # Add content length for payload.
    if payload is not None:
        buf += to_b(f"Content-Length: {len(payload)}\r\n")
    
    # Terminate headers.
    buf = buf[:-2]
    assert(buf[-1] not in [b'\r', b'\n'])
    buf += b"\r\n\r\n"

    # Append payload (if any.)
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

        te = "Transfer-Encoding"
        if te in self.hdrs:
            if self.hdrs[te] == "chunked":
                raise Exception("chunked encodign not supported!")

    def out(self):
        return self.read(self.resp_len)
    
def get_hdr(name, hdrs):
    # Hdrs none probably.
    if not isinstance(hdrs, list):
        return (-1, None)
    
    # Look for particular HTTP header.
    for index, hdr in enumerate(hdrs):
        if hdr[0].lower() == name.lower():
            return (index, hdr[1])
        
    # Not found.
    return (-1, None)

async def http_req(route, dest, path, do_close=1, method=b"GET", payload=None, headers=None, conf=NET_CONF):
    # Get a new con 
    r = copy.deepcopy(route)
    r = await r.bind()
    
    assert(dest is not None)
    log(f"{route} {dest}")
    try:
        p = await pipe_open(route=r, proto=TCP, dest=dest, conf=conf)
    except Exception:
        log_exception()

    if p is None:
        return None, None

    try:
        p.subscribe(SUB_ALL)

        # Set host and port from con service.
        host, port = dest.tup

        # But overwrite host if it's set.
        hdr_index, new_host = get_hdr(b"Host", headers)
        if new_host is not None:
            host = new_host
            del headers[hdr_index]

        # Build raw HTTP request.
        buf = http_req_buf(
            route.af,
            host,
            port,
            path,
            method=method,
            payload=payload,
            headers=headers
        )

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

"""
Break up a URL into it's host, port, file path,
and resolve it's domain as an address for use with
networking code that works to make the HTTP request.
"""
async def url_res(route, url, timeout=3):
        # Split URL into host and port.
        port = 80
        url_parts = urllib.parse.urlparse(url)
        host = netloc = url_parts.netloc
        path = url_parts.path

        # Overwrite default port 80.
        if ":" in netloc:
            host, port = netloc.split(":")
            port = int(port)

        # Resolve domain of URL.
        dest = await Address(
            host,
            port,
            route,
            timeout=timeout
        )

        # Return URL parts.
        return {
            "host": host,
            "port": port,
            "path": path,
            "dest": dest
        }

"""
The purpose of this function is to provide something simple for
fetching a remote URL. The URL param may be pre-resolved using url_res,
otherwise it can be a URL string to fetch. The function accepts optional
GET params. The post method is not supported.
"""
async def url_open(route, url, params={}, timeout=3, throttle=0, headers=[], conf=NET_CONF):
    # Other types for url are not supported.
    url_parts = Exception("url param type is not supported.")

    # url is a URL so break into parts.
    if isinstance(url, str):
        url_parts = await url_res(route, url, timeout=timeout)

    # URL is provided as parts already.
    if isinstance(url, dict):
        url_parts = url

    # Throttle request.
    if throttle:
        await asyncio.sleep(throttle)

    # Encode GET params.
    get_vars = ""
    for name in params:
        # Encode the value.
        v = to_s(
            urlencode(
                params[name]
            )
        )

        # Pass the params in the URL.
        n = to_s(urlencode(name))
        get_vars += f"&{n}={v}"

    # Request path.
    if len(get_vars):
        path = f"{url_parts['path']}?{get_vars}"
    else:
        path = url_parts["path"]

    # Make req.
    conf["con_timeout"] = timeout
    conf["recv_timeout"] = timeout
    headers += [[b"Host", to_b(url_parts["host"])]]
    _, resp = await http_req(
        route,
        url_parts["dest"],
        path,

        # Specify the right sub/domain.
        headers=headers,
        conf=conf
    )

    # Return API output as string.
    return to_s(resp.out())
    
