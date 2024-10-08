import re
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from .utils import *
from .http_client_lib import *
from .daemon import Daemon

P2PD_PORT = 12333
P2PD_CORS = ['null', 'http://127.0.0.1']
P2PD_MIME = [
    [dict, "json"],
    [bytes, "binary"],
    [str, "text"]
]

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


#out = get_params(["sub", "msg_p", "addr_p"], "/sub/con_name/msg_p/test")
#print(out)
#exit(0) 

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
        payload = to_b(payload)
        content_type = b"application/octet-stream"

    if mime == "text":
        payload = to_b(payload)
        content_type = b"text/html"

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
    res = http_res(out, "binary", req, client_tup)
    await pipe.send(res, client_tup)
    await pipe.close()

async def send_text(out, req, client_tup, pipe):
    res = http_res(out, "text", req, client_tup)
    await pipe.send(res, client_tup)
    await pipe.close()

async def rest_service(msg, client_tup, pipe, api_closure=api_closure):
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

"""
d[required or optional] = url
"""
def api_route_closure(url_path):
    # Fields list names a p result and is in a fixed order.
    # Get names matches named values and is in a variable order.
    def api(schemes): 
        # Break up the URL based on slashes.
        out = re.findall("(?:/([^/]+))", url_path)
        as_dict = {}
        unnamed = {}
        out = list(out)

        # Generate a list of matches for schemes across out list.
        def in_schemes(v):
            for i in range(len(schemes)):
                # Use regex to check value.
                scheme = schemes[i]
                if len(scheme) == 3:
                    if scheme[2] == '*':
                        return (i, v, True)
                    
                    if re.match(scheme[2], v) != None:
                        return (i, v, True)
                    else:
                        return (i, scheme[1], True)

                # Compare value only.
                if v == scheme[0]:
                    return (i, v, True)
                    
            return (None, v, False)

        # Supports routing via named params with regex and defaults.
        # Unnamed positional params are returned in another dict.
        i = 0
        schemes_matches = [in_schemes(o) for o in out]
        while len(schemes_matches):
            # Get scheme for associated match.
            scheme_p, val_match, cur_match = schemes_matches[0]
            if scheme_p is not None:
                cur_scheme = schemes[scheme_p]
            else:
                cur_scheme = None

            # Unnamed positional argument.
            if not cur_match:
                unnamed[i] = val_match
                i += 1
                schemes_matches.pop(0)
                continue

            # Don't compare next element.
            if len(schemes_matches) >= 2:
                # Allow checking next element.
                scheme_p, next_val_match, next_match = schemes_matches[1]

                # Next doesn't match so take as a value to this.
                if scheme_p is None and not next_match:
                    val_match = next_val_match
                    if len(cur_scheme) > 1:
                        cur_scheme[1] = next_val_match

                    schemes_matches.pop(0)

            # Substitute a default value.
            if len(cur_scheme) > 1:
                val = cur_scheme[1]
            else:
                val = val_match

            # Set the match.
            as_dict[cur_scheme[0]] = val
            schemes_matches.pop(0)

        return as_dict, unnamed

    return api

class RESTD(Daemon):
    def __init__(self):
        super().__init__()

        # Get a list of function methods for this class.
        # This is needed because sub-classes dynamically add methods.
        methods = [member for member in [getattr(self, attr) for attr in dir(self)] if inspect.ismethod(member)]

        # Loop over class instance methods.
        # Build a list of decorated methods that will form REST API.
        self.apis = {"GET": [], "POST": [], "DELETE": []}
        for f in methods:
            if "REST__" in f.__name__[:7]:
                self.apis[f.http_method].append(f)

    @staticmethod
    def rest_api_decorator(f, args):
        # Allow this method to be looked up.
        f.__name__ = "REST__" + f.__name__

        # Simulate default arguments.
        # Schemes passed in as f(scheme, ...)
        # rather than f([scheme, ...]).
        fargs = []
        for scheme in args:
            fargs.append(scheme)

        # Store the args in the function.
        f.args = fargs

        # Call original function.
        return f

    @staticmethod
    def GET(*args, **kw):
        def decorate(f):
            # Save HTTP method.
            f.http_method = "GET"
            return RESTD.rest_api_decorator(f, args)

        return decorate
    
    @staticmethod
    def POST(*args, **kw):
        def decorate(f):
            # Save HTTP method.
            f.http_method = "POST"
            return RESTD.rest_api_decorator(f, args)

        return decorate
    
    @staticmethod
    def DELETE(*args, **kw):
        def decorate(f):
            # Save HTTP method.
            f.http_method = "DELETE"
            return RESTD.rest_api_decorator(f, args)

        return decorate

    # Todo: $_GET from ?...
    async def msg_cb(self, msg, client_tup, pipe):
        # Parse HTTP message and handle CORS.
        req = await rest_service(msg, client_tup, pipe, api_route_closure)

        # Receive any HTTP payload data.
        body = b""; payload_len = 0
        if "Content-Length" in req.hdrs:
            # Content len must not exceed msg len.
            payload_len = to_n(req.hdrs["Content-Length"])
            if in_range(payload_len, [1, len(msg)]):
                # Last content-len bytes == payload.
                body = msg[-payload_len:]

        # Convert body payload to json.
        if "Content-Type" in req.hdrs:
            if req.hdrs["Content-Type"] == "application/json":
                if payload_len:
                    body = json.loads(to_s(body))

        # Call all matching API routes.
        v = None
        positional_no = 100
        best_matching_api = None
        for api in self.apis[req.command]:
            named, positional = req.api(api.args)

            # Matches /.
            if len(self.apis[req.command]) == 1:
                pass
            else:
                # Not a matching API method.
                if len(named) != len(api.args):
                    continue

            # Find best matching API method.
            if len(positional) < positional_no:
                best_matching_api = api
                positional_no = len(positional)

                # HTTP request info for API methoiid.
                v = {
                    "req": req,
                    "name": named,
                    "pos": positional,
                    "client": client_tup,
                    "body": body
                }

        # Call matching API method.
        if best_matching_api is not None:
            # Get response from wrapped function.
            # Capture any exceptions in the reply.
            try:
                resp = await best_matching_api(v, pipe)
            except Exception as e:
                resp = {
                    "error": "Exception",
                    "msg": str(e),
                }

            # Match output types to the write mime headers.
            for out_info in P2PD_MIME:
                if isinstance(resp, out_info[0]):
                    # Full HTTP reply to client.
                    buf = http_res(
                        resp,
                        out_info[1],
                        req,
                        client_tup
                    )

                    # Send it back to the client.
                    await pipe.send(buf, client_tup)
                    break
                



