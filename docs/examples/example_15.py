from p2pd import *

async def example():
    nic = await Interface()
    addr = ("93.184.215.14", 80)
    curl = WebCurl(addr, nic.route(IP4))
    params = {"action": "upload"}
    payload = b"Data to POST!"
    resp = await curl.vars(
        url_params=params,
        body=payload
    ).post("/meow/cat.php")
    print(resp.out)

if __name__ == '__main__':
    async_test(example)