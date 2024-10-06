from p2pd import *

# Every website today seems to want Javascript
# but its an example and demonstrates SSL too.
async def example():
    # Setup HTTP params.
    addr = ("www.google.com", 443)
    params = {"q": "lets search!"}
    path = "/search"
    conf = dict_child({
        "use_ssl": True
    }, NET_CONF)

    # Load interface and route to use.
    nic = await Interface()
    curl = WebCurl(addr, nic.route(IP4))

    # Make the web request.
    resp = await curl.vars(params).get(path, conf=conf)
    print(resp.req_buf)
    print(resp.out)

if __name__ == '__main__':
    async_test(example)