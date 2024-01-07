import re
from p2pd import *
from p2pd.netiface_extra import get_mac_mixed


async def test_mac():
    out = await get_mac_mixed("Intel(R) Wi-Fi 6E AX211 160MHz")
    print(out, end="")

async_test(test_mac)