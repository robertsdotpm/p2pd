from p2pd import *

async def example():
    i = await Interface().start()
    addr = await Address("93.184.215.14", 80, i.route())
    curl = WebCurl(addr)
    params = {"action": "upload"}
    payload = b"Data to POST!"
    resp = await curl.vars(
        url_params=params,
        body=payload
    ).post("/meow/cat.php")
    print(resp.out)

if __name__ == '__main__':
    async_test(example)