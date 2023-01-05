import re
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from .utils import *
from .http_client_lib import *

P2PD_PORT = 12333
P2PD_CORS = ['null', 'http://127.0.0.1']

# Support passing in GET params using path seperators.
# Ex: /timeout/10/sub/all -> {'timeout': '10', 'sub': 'all'}
def get_params(field_names, url_path):
    # Return empty.
    if field_names == []:
        return {}

    # Build regex match string.
    p = ""
    for field in field_names:
        # Escape any regex-specific characters.
        as_literal = re.escape(field)
        as_literal = as_literal.replace("/", "")

        # (/ field name / non dir chars )
        # All are marked as optional.
        p += f"(?:/({as_literal})/([^/]+))|"

    # Repeat to match optional instances of the params.
    p = f"(?:{p[:-1]})+"

    # Convert the marked pairs to a dict.
    params = {}
    safe_url = re.escape(url_path)
    results = re.findall(p, safe_url)
    if len(results):
        results = results[0]
        for i in range(0, int(len(results) / 2)):
            # Every 2 fields is a named value.
            name = results[i * 2]
            value = results[(i * 2) + 1]
            value = re.unescape(value)

            # Param not set.
            if name == "":
                continue

            # Save by name.
            name = re.unescape(name)
            params[name] = value

    # Return it for use.
    return params

def api_closure(url_path):
    # Fields list names a p result and is in a fixed order.
    # Get names matches named values and is in a variable order.
    def api(p, field_names=[], get_names=[]): 
        out = re.findall(p, url_path)
        as_dict = {}
        if len(out):
            if isinstance(out[0], tuple):
                out = out[0]

            if len(field_names):
                for i in range(  min( len(out), len(field_names) )  ):
                    as_dict[field_names[i]] = out[i]
            else:
                as_dict["out"] = out
            

        params = get_params(get_names, url_path)
        if len(params) and len(as_dict):
            return dict_merge(params, as_dict)
        else:
            return as_dict

    return api

# p = {}, optional = [ named ... ]
# default = [ matching values ... ]
def set_defaults(p, optional, default):
    # Set default param values.
    for i, named in enumerate(optional):
        if named not in p:
            p[named] = default[i]

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

async def rest_service(msg, client_tup, pipe):
    # Parse http request.
    try:
        req = ParseHTTPRequest(msg)
    except Exception:
        log_exception()
        return None

    # Deny restricted origins.
    if req.hdrs["Origin"] not in P2PD_CORS:
        resp = {
            "msg": "Invalid origin.",
            "error": 5
        }
        await send_json(resp, req, client_tup, pipe)
        return None

    # Implements 'pre-flight request checks.'
    cond_1 = "Access-Control-Request-Method" in req.hdrs
    cond_2 = "Access-Control-Request-Headers" in req.hdrs
    if cond_1 and cond_2:
        # CORS policy header line.
        allow_origin = "Access-Control-Allow-Origin: %s" % (
            req.hdrs["Origin"]
        )

        # HTTP response.
        out  = b"HTTP/1.1 200 OK\r\n"
        out += b"Content-Length: 0\r\n"
        out += b"Connection: keep-alive\r\n"
        out += b"Access-Control-Allow-Methods: POST, GET, DELETE\r\n"
        out += b"Access-Control-Allow-Headers: *\r\n"
        out += b"%s\r\n\r\n" % (to_b(allow_origin))
        await pipe.send(out, client_tup)
        return None

    # Critical URL path part is encoded.
    url_parts = urllib.parse.urlparse(req.path)
    url_path = urllib.parse.unquote(url_parts.path)
    url_query = urllib.parse.parse_qs(url_parts.query)
    req.url = {
        "parts": url_parts,
        "path": url_path,
        "query": url_query
    }

    req.api = api_closure(url_path)
    return req