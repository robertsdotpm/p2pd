"""
Adapted from the excellent code here.

https://gist.github.com/mrpapercut/92422ecf06b5ab8e64e502da5e33b9f7

- Need to add a list of opennic servers for IP4 and IP6
then select one depending on the route af
- random id prob?
- select a or AAAA based on route if type is none

- maybe more complex code that sends out multiple requests and returns first result

Notes: On big websites that use 'DNS round robin' to distribute load between
servers its common for the function to return only one IP. On websites
with multiple a records the code still returns multiple results. I've
tested this works with openai.com but this depends on the name server.

See https://web.archive.org/web/20180919041301/https://routley.io/tech/2017/12/28/hand-writing-dns-messages.html
See https://tools.ietf.org/html/rfc1035
"""

import binascii
import copy
import time
from .settings import *
from .utils import *
from .net import *
from .ip_range import IPRange
from .address import Address
from .base_stream import pipe_open

def dns_get_type(type):
    types = {
        "A": 1,
        "NS": 2,
        "MD": 3,
        "MF": 4,
        "CNAME": 5,
        "SOA": 6,
        "MB": 7,
        "MG": 8,
        "MR": 9,
        "NULL": 10,
        "WKS": 11,
        "PTS": 12,
        "HINFO": 13,
        "MINFO": 14,
        "MX": 15,
        "TXT": 16,
        "AAAA": 28
    }

    # Return ID as unsigned short in hex (0 padded if needed.)
    if isinstance(type, str):
        return "{:04x}".format(types[type])
    else:
        # Return record type.
        for k in types:
            if types[k] == type:
                return k

def dns_build_message(type="A", address=""):
    # Todo: rand ID for request here.
    ID = 43690  # 16-bit identifier (0-65535) # 43690 equals 'aaaa'

    QR = 0      # Query: 0, Response: 1     1bit
    OPCODE = 0  # Standard query            4bit
    AA = 0      # ?                         1bit
    TC = 0      # Message is truncated?     1bit
    RD = 1      # Recursion?                1bit
    RA = 0      # ?                         1bit
    Z = 0       # ?                         3bit
    RCODE = 0   # ?                         4bit

    query_params = str(QR)
    query_params += str(OPCODE).zfill(4)
    query_params += str(AA) + str(TC) + str(RD) + str(RA)
    query_params += str(Z).zfill(3)
    query_params += str(RCODE).zfill(4)
    query_params = "{:04x}".format(int(query_params, 2))

    QDCOUNT = 1 # Number of questions           4bit
    ANCOUNT = 0 # Number of answers             4bit
    NSCOUNT = 0 # Number of authority records   4bit
    ARCOUNT = 0 # Number of additional records  4bit

    message = ""
    message += "{:04x}".format(ID)
    message += query_params
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    # QNAME is url split up by '.', preceded by int indicating length of part
    addr_parts = address.split(".")
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        message += addr_len
        message += addr_part.decode()

    message += "00" # Terminating bit for QNAME

    # Type of request
    QTYPE = dns_get_type(type)
    message += QTYPE

    # Class for lookup. 1 is Internet
    QCLASS = 1
    message += "{:04x}".format(QCLASS)

    return message

def dns_parse_parts(message, start, parts):
    part_start = start + 2
    part_len = message[start:part_start]
    
    if len(part_len) == 0:
        return parts
    
    part_end = part_start + (int(part_len, 16) * 2)
    parts.append(message[part_start:part_end])

    if message[part_end:part_end + 2] == "00" or part_end > len(message):
        return parts
    else:
        return dns_parse_parts(message, part_end, parts)

def dns_decode_message(message):    
    result_dict = {}
    ID = message[0:4]
    query_params = message[4:8]
    QDCOUNT = message[8:12]
    ANCOUNT = message[12:16]
    NSCOUNT = message[16:20]
    ARCOUNT = message[20:24]

    # Param section.
    params = "{:b}".format(int(query_params, 16)).zfill(16)
    QPARAMS = {
        "qr": params[0:1],
        "opcode": params[1:5],
        "aa": params[5:6],
        "tc": params[6:7],
        "rd": params[7:8],
        "ra": params[8:9],
        "z": params[9:12],
        "rcode": params[12:16]
    }

    # Question section.
    QUESTION_SECTION_STARTS = 24
    question_parts = dns_parse_parts(message, QUESTION_SECTION_STARTS, [])
    QNAME = ".".join(map(lambda p: binascii.unhexlify(p).decode(), question_parts))    
    QTYPE_STARTS = QUESTION_SECTION_STARTS + (len("".join(question_parts))) + (len(question_parts) * 2) + 2
    QCLASS_STARTS = QTYPE_STARTS + 4
    QTYPE = message[QTYPE_STARTS:QCLASS_STARTS]
    QCLASS = message[QCLASS_STARTS:QCLASS_STARTS + 4]

    # Header section.
    result_dict["header"] = {
        "id": ID,
        "queryparams": QPARAMS,
        "question": {
            "qname": QNAME,
            "qtype": dns_get_type(int(QTYPE, 16)),
            "qclass": QCLASS
        }
    }

    # Process answers.
    answers = []
    ANSWER_SECTION_STARTS = QCLASS_STARTS + 4
    while ANSWER_SECTION_STARTS < len(message):
        answer = {}
        ANAME = message[ANSWER_SECTION_STARTS:ANSWER_SECTION_STARTS + 4]
        ATYPE = message[ANSWER_SECTION_STARTS + 4:ANSWER_SECTION_STARTS + 8]
        ACLASS = message[ANSWER_SECTION_STARTS + 8:ANSWER_SECTION_STARTS + 12]
        TTL = int(message[ANSWER_SECTION_STARTS + 12:ANSWER_SECTION_STARTS + 20], 16)
        RDLENGTH = int(message[ANSWER_SECTION_STARTS + 20:ANSWER_SECTION_STARTS + 24], 16)
        RDDATA = message[ANSWER_SECTION_STARTS + 24:ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)]

        if ATYPE == dns_get_type("A"):
            octets = [RDDATA[i:i+2] for i in range(0, len(RDDATA), 2)]
            RDDATA_decoded = ".".join(list(map(lambda x: str(int(x, 16)), octets)))
        elif ATYPE == dns_get_type("AAAA"):  # IPv6 record
            hextets = [RDDATA[i:i+4] for i in range(0, len(RDDATA), 4)]
            RDDATA_decoded = ":".join(hextets)
        else:
            RDDATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), dns_parse_parts(RDDATA, 0, [])))

        answer["aname"] = ANAME
        answer["atype"] = ATYPE
        answer["aclass"] = ACLASS
        answer["ttl"] = TTL
        answer["rdlength"] = RDLENGTH
        answer["rddata"] = RDDATA
        answer["rddata_decoded"] = RDDATA_decoded
        answers.append(answer)

        ANSWER_SECTION_STARTS = ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)

    # Return results.
    result_dict["answers"] = answers
    return result_dict

def dns_to_list(msg, record_type):
    # Extract the answers section.
    results = []
    answers = msg.get("answers", [])
    for answer in answers:
        # Only append result if it's an IP.
        if record_type in ["A", "AAAA"]:
            try:
                IPRange(answer["rddata_decoded"])
                results.append(answer["rddata_decoded"])
            except:
                continue
        else:
            results.append(answer["rddata_decoded"])

    return results

class DNSClient():
    def __init__(self, route):
        self.route = route

    # TODO: doesnt handle packet drops
    async def req(self, domain_name, record_type="A", ns=None):
        # Choose a random name server.
        if ns is None:
            ns = random.choice(
                NS_SERVERS[self.route.af]
            )

        # Bind a route to unused port.
        # Use route as a template.
        route = copy.deepcopy(self.route)
        route = await route.bind()

        # Get address tuple for name server.
        # Will throw if ns is not an IP.
        IPRange(ns)
        addr = await Address(ns, 53, route)

        # Create async UDP pipe to name server.
        pipe = await pipe_open(UDP, route, addr)
        try:
            # Create DNS to send to name server.
            msg = dns_build_message(record_type, domain_name)
            buf = binascii.unhexlify(msg)

            # Send DNS request.
            await pipe.send(buf)

            # Get reply DNS reply.
            data = await pipe.recv()

            # Parse reply to a dictionary.
            data = binascii.hexlify(data).decode("utf-8")
            data = dns_decode_message(data)

            # Return reply as a simple list of results.
            return dns_to_list(data, record_type)
        finally:
            if pipe is not None:
                await pipe.close()

async def test_dns():
    from .interface import Interface

    i = await Interface().start_local()
    route = i.route(IP4)
    client = DNSClient(route)

    a = time.time()

    # openai for multiple results ipv4
    # reddit has multiple ipv6 results and TXT records
    # http://grep.geek/ for opennic
    ret = await client.req("reddit.com", record_type="AAAA")
    b = time.time() - a
    print(b)
    #print(pprint.pformat(ret))

    #print(t)
    print(ret)

async_test(test_dns)

