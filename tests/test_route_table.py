import multiprocessing
import platform

from p2pd import IP4, IP6, Interface
from p2pd.cmd_tools import *
from p2pd.net import VALID_AFS
from p2pd.route_table import get_route_table, is_internet_if
from p2pd.test_init import *

RELATED_PLATFORMS = ["Linux", "Darwin", "FreeBSD"]


class TestRouteTable(unittest.IsolatedAsyncioTestCase):
    async def test_route_table(self):
        if platform.system() in RELATED_PLATFORMS:
            netifaces = await init_p2pd()

        applies = False
        one_worked = False
        for af in VALID_AFS:
            if platform.system() in RELATED_PLATFORMS:
                applies = True
                try:
                    table = await get_route_table(af)
                    if not len(table):
                        continue

                    # Get a default interface.
                    i = Interface(netifaces=netifaces)

                    # Check that the func to test internet interfaces works.
                    if i.nic_no:
                        # Bug here on Windows but Windows doesn't depend on this logic.
                        r = await is_internet_if(i.nic_no)
                    else:
                        r = await is_internet_if(i.name)

                    one_worked = True
                except Exception:
                    log_exception()
                    pass

        if applies:
            if not one_worked:
                print("The route table code failed.")
                print("If the system has a route command this may be an error.")


if __name__ == '__main__':
    main()
