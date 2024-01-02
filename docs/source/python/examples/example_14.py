from p2pd import *

async def example():
    i = await Interface().start()
    addr = await Address("www.example.com", 80, i.route())
    curl = WebCurl(addr)
    url_params = {"q": "lets search!"}
    resp = await curl.vars(url_params).get("/")
    print(resp.out)

if __name__ == '__main__':
    async_test(example)