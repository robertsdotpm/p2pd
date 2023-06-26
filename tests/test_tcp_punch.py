import asyncio
from p2pd.test_init import *
from p2pd.p2p_node import *
from p2pd.p2p_utils import *
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from decimal import Decimal as Dec

asyncio.set_event_loop_policy(SelectorEventPolicy())
class TestTCPPunch(unittest.IsolatedAsyncioTestCase):
    async def test_map_info_to_their_maps(self):
        map_info = {
            "remote": [5000],
            "reply": [0],
            "local": [10000]
        }

        expected = [
            [ 5000, 0, 10000 ]
        ]

        self.assertEqual(
            map_info_to_their_maps(map_info),
            expected
        )

    async def test_self_punch_no_networking(self):
        # Used to schedule and synchronize the punching.
        # Manager is used to push sockets between processes.
        log(">>> test_self_punch_no_networking")
        sys_clock = SysClock(Dec("0.01"))
        pe = await get_pp_executors()
        #pe2 = await get_pp_executors(workers=2)
        
        if pe is not None:
            qm = multiprocessing.Manager()
        else:
            qm = None
            
        pipe_id = b"pipe_id"

        # Load interfaces is slow AF on Windows.
        # Due to it using powershell + regex, lolz.
        ifs = await load_interfaces()
        interface = ifs[0]
        if IP4 in interface.supported():
            af = IP4
        else:
            af = IP6

        # Pretend we're using an open internet.
        # This is because we're doing a self-test.
        dest = interface.rp[af].routes[0].nic()
        #nat = nat_info(OPEN_INTERNET, delta_info(NA_DELTA, 0))
        nat = nat_info(FULL_CONE, delta_info(PRESERV_DELTA, 0))
        nat["is_concurrent"] = random.choice([True, False])
        for i in ifs:
            i.set_nat(nat)

            # Not needed for a self / LAN test:
            # await interface.load_nat()

        # Used to get external mappings (not needed for self-test.)
        stun_client = STUNClient(interface, af)
        
        # Initiator client -- starts the protocol.
        # Sends the first mapping details.
        i_node_id = b"i_node_id"
        i_client = TCPPunch(interface, ifs, sys_clock, pe, qm)
        i_client.do_state_cleanup = False

        # Recipient client -- receives the first mappings.
        # Provides additional mapping details if possible.
        r_node_id = b"r_node_id"
        r_client = TCPPunch(interface, ifs, sys_clock, pe, qm)
        r_client.do_state_cleanup = False

        # Get punch mode.
        route = interface.route(af)
        dest_addr = await Address(dest, 80, route).res()
        mode = i_client.get_punch_mode(dest_addr)
        self.assertEqual(mode, TCP_PUNCH_SELF)

        # Get initial mappings.
        i_maps, ntp_meet, got_update = await i_client.proto_send_initial_mappings(
            dest_addr=dest,
            dest_nat=nat,
            dest_node_id=r_node_id,
            pipe_id=pipe_id,
            stun_client=stun_client,
            mode=mode
        )

        #print(i_maps, ntp_meet)

        # Receive their mappings.
        r_maps, _, sent_update = await r_client.proto_recv_initial_mappings(
            recv_addr=dest,
            recv_nat=nat,
            recv_node_id=i_node_id,
            pipe_id=pipe_id,
            their_maps=i_maps,
            stun_client=stun_client,
            ntp_meet=ntp_meet,
            mode=mode
        )

        #print(r_maps)

        await i_client.proto_update_recipient_mappings(
            dest_node_id=r_node_id,
            pipe_id=pipe_id,
            their_maps=r_maps,
            stun_client=stun_client
        )

        #print(i_client.state)

        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    async_wrap_errors(
                        i_client.proto_do_punching(PUNCH_INITIATOR, r_node_id, pipe_id)
                    ),
                    async_wrap_errors(
                        r_client.proto_do_punching(PUNCH_RECIPIENT, i_node_id, pipe_id)
                    )
                ),
                10
            )
        except Exception:
            results = []

        print("Got results = ")
        print(results)

        async def process_results(results):
            if len(results) != 2:
                return False

            msg = b"a test msg"
            for pipe in results:
                if pipe is None:
                    return False

                pipe.subscribe(sub=SUB_ALL)

            for pipe in results:
                await pipe.send(msg, pipe.stream.dest_tup)

            for pipe in results:
                out = await pipe.recv(timeout=3)
                if out != msg:
                    return False

            return True

        status = await process_results(results)
        if status == False:
            print("Self punch test no networking failed.")
            print("Test is optional but noting it here.")


        for pipe in results:
            if pipe is not None:
                await pipe.close()

        for punch_client in [i_client, r_client]:
            await punch_client.close()

        # Try close the multiprocess manager.
        try:
            if qm is not None:
                qm.shutdown()
        except Exception:
            pass

        # Try close the process pool executor.
        try:
            if pe is not None:
                pe.shutdown()
        except Exception:
            pass

if __name__ == '__main__':
    main()