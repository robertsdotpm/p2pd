from p2pd.test_init import *
from p2pd.nat import *

class TestNAT(unittest.IsolatedAsyncioTestCase):
    async def test_preserving_delta(self):
        fake_stun = FakeSTUNClient(interface=None)
        fake_stun.set_mappings([
            [ 4000, 50000 ],
            [ 10000, 56000 ],
            [ 10200, 56200 ],
            [ 10400, 56400 ],
            [ 11000, 57000 ], # threshold passed.
            [ 12000, 58000 ],
            [ 4620, 2333 ], # wrong
            [ 4630, 2334 ], # wrong
        ])

        expected = delta_info(PRESERV_DELTA, 0)
        got = await delta_test(fake_stun, concurrency=False)
        self.assertEqual(expected, got)

    async def test_equal_delta(self):
        fake_stun = FakeSTUNClient(interface=None)
        fake_stun.set_mappings([
            [ 4567, 4567 ],
            [ 48234, 48234 ],
            [ 6823, 6823 ],
            [ 60000, 60000 ],
            [ 50000, 50000 ], # threshold passed.
            [ 60001, 60001 ],
            [ 5000, 5001 ], # wrong
            [ 5000, 5001 ], # wrong
        ])

        expected = delta_info(EQUAL_DELTA, 0)
        got = await delta_test(fake_stun, concurrency=False)
        self.assertEqual(expected, got)

    async def test_independent_delta(self):
        fake_stun = FakeSTUNClient(interface=None)
        fake_stun.set_mappings([
            [ 5000, 50000 ],
            [ 23412, 50010 ],
            [ 55421, 50020 ],
            [ 6322, 50030 ],
            [ 5622, 50040 ], # threshold passed.
            [ 45610, 50050 ],
            [ 4420, 2333 ], # wrong
            [ 5555, 2334 ], # wrong
        ])

        expected = delta_info(INDEPENDENT_DELTA, 10)
        got = await delta_test(fake_stun, concurrency=False)
        self.assertEqual(expected, got)

    async def test_dependent_delta(self):
        fake_stun = FakeSTUNClient(interface=None)
        fake_stun.set_mappings([
            [ 4560, 50000 ],
            [ 4561, 50020 ],
            [ 4562, 50040 ],
            [ 4563, 50060 ],
            [ 4564, 50080 ], # threshold passed.
            [ 4565, 50100 ],
            [ 4566, 2333 ], # wrong
            [ 4567, 6000 ], # wrong
        ])

        expected = delta_info(DEPENDENT_DELTA, 20)
        got = await delta_test(fake_stun, concurrency=False)
        self.assertEqual(expected, got)

    async def test_random_delta(self):
        fake_stun = FakeSTUNClient(interface=None)
        fake_stun.set_mappings([
            [ 4560, 4443 ],
            [ 4561, 50001 ],
            [ 4562, 63813 ],
            [ 4563, 64000 ],
            [ 4564, 2000 ], # threshold passed.
            [ 4565, 6004 ],
            [ 4566, 2333 ], # wrong
            [ 4567, 8432 ], # wrong
        ])

        expected = delta_info(RANDOM_DELTA, 0)
        got = await delta_test(fake_stun, concurrency=False)
        self.assertEqual(expected, got)

    async def test_nat_intersect_range(self):
        tests = [
            [
                [2000, 10000],
                [5000, 20000],
                [5000, 10000]
            ],
            [
                [2000, 10000],
                [2000, 10000],
                [2000, 10000],
            ],
            [
                [2000, 10000],
                [9999, 10000],
                [9999, 10000],
            ],
        ]

        for test in tests:
            nat_a = nat_info(OPEN_INTERNET,
                delta_info(NA_DELTA, 0),
                test[0]
            )

            nat_b = nat_info(OPEN_INTERNET,
                delta_info(NA_DELTA, 0),
                test[1]
            )

            expected = test[2]
            got = nats_intersect_range(nat_a, nat_b, 0)
            self.assertEqual(got, expected)

    async def test_get_single_mapping(self):
        # Attempt to mimic other sides remote ports.
        mode = TCP_PUNCH_REMOTE

        # What their mappings look like.
        # [ remote, reply, local ] of peers mapping.
        rmap = [ 13073, 0, 50000 ]

        # Last mapped used as starting point for some NAT types.
        # First or last STUN lookup values.
        # [ local, remote ]
        last_mapped = [ 44333, 30000 ]

        # Range that their mappings are in (assume full range.)
        use_range = [ 5000, 68000 ]

        # Fake STUN client used to test logic paths.
        i = None; af = IP4; our_nat = None;
        stun_client = FakeSTUNClient(interface=i, af=af)

        # All params to pass to func.
        params = [ mode, rmap, last_mapped, use_range, our_nat, stun_client ]
        f_check = lambda e, r: r[0][:3] == e

        ##########################################################
        # Case 1 = Our NAT is fully open.
        params[-2] = nat_info(OPEN_INTERNET, delta_info(NA_DELTA, 0))
        # [ local, remote, reply ]
        expected = [ rmap[0], rmap[0], 0 ]
        ret = await get_single_mapping(*params)
        self.assertTrue(f_check(expected, ret))

        ##########################################################
        # Case 2 = Our NAT can preserve local ports.
        params[-2] = nat_info(FULL_CONE, delta_info(EQUAL_DELTA, 0))
        expected = [ rmap[0], rmap[0], 0 ]
        ret = await get_single_mapping(*params)
        self.assertTrue(f_check(expected, ret))

        ##########################################################
        # Case 3 = Our delta preserves the distance between locals.
        params[-2] = nat_info(RESTRICT_PORT_NAT, delta_info(PRESERV_DELTA, 0))
        """
        n_dist = ( last_remote (30000), bind_port (13073) )
               = 16927
        last_local = 44333 (maps to the last remote)
        next_local = port_wrap(last_local + n_dist)
                   = 61260
        """
        expected = [ 61260, rmap[0], rmap[0] ]
        ret = await get_single_mapping(*params)
        self.assertTrue(f_check(expected, ret))

        ##########################################################
        # Case 4 = Each new mapping is + delta value.
        delta_val = 4
        params[-2] = nat_info(
            RESTRICT_NAT,
            delta_info(INDEPENDENT_DELTA, delta_val)
        )
        ret = await get_single_mapping(*params)
        expected = [ 
            ret[0][0],
            last_mapped[1] + delta_val,
            0
        ]
        self.assertTrue(f_check(expected, ret))

        ##########################################################
        # Case 5 = Each new mapping is + delta value.
        # Only if local ports also increase sequentially.
        params[-2] = nat_info(
            RESTRICT_NAT,
            delta_info(DEPENDENT_DELTA, delta_val)
        )
        expected = [ 
            last_mapped[0] + 1,
            last_mapped[1] + delta_val,
            0
        ]
        ret = await get_single_mapping(*params)
        self.assertTrue(f_check(expected, ret))

        ##########################################################
        # Case 6 = Reusable mapping from same local port.
        params[-2] = nat_info(
            FULL_CONE,
            delta_info(RANDOM_DELTA, 0)
        )

        stun_client.set_mappings([[44444, 33333]])
        expected = [44444, 33333, 0 ]
        ret = await get_single_mapping(*params)
        self.assertTrue(f_check(expected, ret))

        

    
if __name__ == '__main__':
    main()

"""
is_valid_rmap

type 5 nat and random delta inside a vmware 'nat' vm behind a router with a cone type nat and preserving delta.
"""
