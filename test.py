from p2pd import *

async def workspace():


    d = xmltodict.parse(x)
    print(d)

    return

    # Setup HTTP params.
    addr = ("88.99.211.216", 80)
    path = "/win-auto-py3/"

    # Load interface and route to use.
    nic = await Interface()
    curl = WebCurl(addr, nic.route(IP4))

    # Make the web request.
    resp = await curl.vars().get(path)
    print(resp.req_buf)
    #print(len(resp.out))

asyncio.run(workspace())