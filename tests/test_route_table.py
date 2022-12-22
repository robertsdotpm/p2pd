from p2pd.test_init import *
import platform
import multiprocessing
from p2pd.net import VALID_AFS
from p2pd.cmd_tools import *
from p2pd import Interface, IP4, IP6
from p2pd.route_table import is_internet_if, get_route_table

class TestRouteTable(unittest.IsolatedAsyncioTestCase):
    async def test_route_table(self):
        one_worked = False
        applies = False
        for af in VALID_AFS:
            if platform.system() in ["Linux", "Darwin", "FreeBSD"]:
                applies = True
                try:
                    table = await get_route_table(af)

                    # Get a default interface.
                    i = Interface()

                    # Check that the func to test internet interfaces works.
                    if i.nic_no:
                        # Bug here on Windows but Windows doesn't depend on this logic.
                        r = await is_internet_if(i.nic_no)
                    else:
                        r = await is_internet_if(i.name)
                        
                    self.assertTrue(r)
                    one_worked = True
                except Exception:
                    log_exception()
                    pass

        if applies:
            self.assertTrue(one_worked)


if __name__ == '__main__':
    multiprocessing.set_start_method("spawn")
    main()