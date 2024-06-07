from p2pd import *
from p2pd.scripts.test_pnp_from_server import PNP_TEST_ENC_SK

async def main():
    i = await Interface().start_local()
    dest = await Address("2a01:04f8:010a:3ce0:0000:0000:0000:0002", PNP_PORT)
    dest_pk = "0249fb385ed71aee6862fdb3c0d4f8b193592eca4d61acc983ac5d6d3d3893689f"
    client = PNPClient(PNP_TEST_ENC_SK, dest, dest_pk)

    name = "my_test_name"
    await client.push(name, "val")
    out = await client.fetch(name)
    print(out.value)
    assert(out == b"val")

async_test(main)