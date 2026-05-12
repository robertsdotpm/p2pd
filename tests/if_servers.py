from aionetiface import *
from aionetiface.testing import AsyncTestCase
from warpgate import *


class TestInterface(AsyncTestCase):
    async def test_if(self):
        try:
            if_names = await list_interfaces()
            print(if_names)

            ifs = await load_interfaces(if_names, Interface, skip_nat=True)
            print(ifs)
        except asyncio.CancelledError:
            raise
        except Exception:
            log_exception()
            ifs = []

        return
        ifs = {0: await Interface()}

        stun_clients = await load_stun_clients(ifs)
        print(stun_clients)

        return
        if_names = await list_interfaces()
        print(if_names)

        out = await load_interfaces(["ens34", "ens37"], Interface)
        print(out)

        return
        n_times = []
        for i in range(0, 20):
            try:
                nic = await Interface()
                start_time = time.time()
                await nic.load_nat(timeout=10)
                stop_time = time.time()
                elapsed = stop_time - start_time
                n_times.append(elapsed)
                print(elapsed)
            except Exception:
                continue

        x = sum(n_times) / len(n_times)
        print(x)


if __name__ == "__main__":
    main()
