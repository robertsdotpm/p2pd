from p2pd import *

async def example():
    i = await Interface().start()
    addr = ("93.184.215.14", 80)
    curl = WebCurl(addr, i.route(IP4))
    url_params = {"q": "lets search!"}
    resp = await curl.vars(url_params).get("/")
    print(resp.out)

if __name__ == '__main__':
    async_test(example)