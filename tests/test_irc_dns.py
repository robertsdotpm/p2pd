"""
    async def test_irc_dns():
        # The 'scanner' was basically this initially.
        # might as well get it working again so it can be reused.
        tasks = []
        for server in IRC_SERVERS1:
            task = async_wrap_errors(IRCDNS(server).start(i))
            tasks.append(task)

        out = await asyncio.gather(*tasks)
        print(out)
        out = strip_none(out)
        print(out)
        return
"""

import pprint
from p2pd.test_init import *
from p2pd import *

IRC_SEED = b"123" * 30
IRC_SERV_INFO = {
    'domain': 'example.com',
    'afs': [IP4, IP6],

    # 6 nov 2000
    'creation': 975848400,

    'nick_serv': ["password", "email"],

    "ip": {
        IP4: "93.184.216.34",
        IP6: "2606:2800:220:1:248:1893:25c8:1946]"
    },

    'chan_len': 50,
    'chan_no': 60,
    'topic_len': 300,
    'chan_topics': 'a-zA-Z0-9all specials unicode (smilies tested)'
}

IRC_S = IRCSession(IRC_SERV_INFO, IRC_SEED)

IRC_TEST_SERVERS_SEVEN = [
    {"domain": "a", "chan_expiry": 14, "nick_expiry": 14},
    {"domain": "b", "chan_expiry": 14, "nick_expiry": 14},
    {"domain": "c", "chan_expiry": 14, "nick_expiry": 14},
    {"domain": "d", "chan_expiry": 14, "nick_expiry": 14},
    {"domain": "e", "chan_expiry": 14, "nick_expiry": 14},
    {"domain": "f", "chan_expiry": 14, "nick_expiry": 14},
    {"domain": "g", "chan_expiry": 14, "nick_expiry": 14},
]

class MockIRCChan(IRCChan):
    async def set_topic(self, topic):
        self.pending_topic = topic

class MockIRCSession(IRCSession):
    async def start(self, i):
        if self.db is not None:
            last_started_key = self.db_key("last_started")
            await self.db.put(last_started_key, time.time())

            # Save user details if needed.
            nick_key = self.db_key("nick")
            await self.db.put(nick_key, {
                "domain": self.irc_server,
                "nick": self.nick,
                "username": self.username,
                "user_pass": self.user_pass,
                "email": self.email,
                "last_refresh": time.time()
            })

        self.started.set_result(True)

    async def is_chan_registered(self, chan_name):
        if chan_name not in self.chan_registered:
            return False
        else:
            return self.nick
    
    async def register_chan(self, chan_name):
        self.chan_registered[chan_name] = True

    async def get_chan_topic(self, chan_name):
        return self.chans[chan_name].pending_topic


# python -m unittest test_irc_dns.TestIRCDNS.
class TestIRCDNS(unittest.IsolatedAsyncioTestCase):
    async def test_proto_ping(self):
        msg = IRCMsg(cmd="PING", param="31337")
        resp = irc_proto(None, msg)
        assert(resp.pack() == b"PONG 31337\r\n")

        msg = IRCMsg(cmd="PING", suffix="31337")
        resp = irc_proto(None, msg)
        assert(resp.pack() == b"PONG :31337\r\n")

    async def test_proto_ctcp_version(self):
        msg = IRCMsg(
            cmd="PRIVMSG",
            prefix="user!ident@host",
            suffix="\x01VERSION\x01"
        )

        resp = irc_proto(None, msg)
        expected = to_b(f"PRIVMSG user :\x01VERSION {IRC_VERSION}\x01\r\n")
        assert(resp.pack() == expected)

    async def test_proto_is_chan_reg(self):
        chan_founder = "chan_founder"
        chan_name = "#test-wrwerEWER342"
        vectors = [
            [f"channel {chan_name} isn't", False],
            [f"channel {chan_name} is not", False],
            [f"information for {chan_name}", chan_founder],
            [f"information on {chan_name}", chan_founder],
            [f"channel {chan_name} is registered", chan_founder]
        ]

        for vector in vectors:
            IRC_S.chan_infos[chan_name] = asyncio.Future()

            status, expected = vector
            msg = IRCMsg(
                cmd="NOTICE",
                param="your_nick",
                suffix=status
            )

            irc_proto(IRC_S, msg)

            if expected:
                msg = IRCMsg(
                    cmd="NOTICE",
                    param="your_nick",
                    suffix=f"Founder : {chan_founder}"
                )

                irc_proto(IRC_S, msg)

            assert(IRC_S.chan_infos[chan_name].result() == expected)

    async def test_proto_get_topic(self):
        chan_name = "#test-CAJANS324"
        chan_topic = B92_CHARSET + " " + B92_CHARSET
        msg = IRCMsg(
            cmd="332",
            param=f"nick {chan_name}",
            suffix=chan_topic
        )

        IRC_S.chan_topics[chan_name] = asyncio.Future()
        irc_proto(IRC_S, msg)
        assert(IRC_S.chan_topics[chan_name].result() == chan_topic)

    async def test_irc_extract_msg(self):
        vectors = [
            [
                "CMD value\r\n",
                IRCMsg(cmd="CMD", param="value")
            ],
            [
                ":test CMD v\r\n",
                IRCMsg(
                    prefix="test",
                    cmd="CMD",
                    param="v"
                )
            ],
            [
                "CMD v :suffix\r\n",
                IRCMsg(
                    suffix="suffix",
                    cmd="CMD",
                    param="v"
                )
            ],
            [
                ":prefix-part CMD v long param :suffix part\r\n",
                IRCMsg(
                    prefix="prefix-part",
                    cmd="CMD",
                    param="v long param",
                    suffix="suffix part"
                )
            ],
            [
                ":prefix-part   CMD  v long param :suffix part\r\n",
                IRCMsg(
                    prefix="prefix-part",
                    cmd="CMD",
                    param="v long param",
                    suffix="suffix part"
                )
            ],
        ]

        for vector in vectors:
            buf, expected = vector
            got, _ = irc_extract_msgs(buf)
            got = got[0]
            assert(got == expected)

    async def test_irc_extract_sender(self):
        vectors = [
            [
                "nickaAWE234 asd",
                {
                    "nick": "nickaAWE234 asd",
                    "user": "",
                    "host": ""
                }
            ],
            [
                "nickaAWE234 asd@hostwe12 S",
                {
                    "nick": "nickaAWE234 asd",
                    "user": "",
                    "host": "hostwe12 S"
                }
            ],
            [
                "nickaAWE234 asd!user sF S",
                {
                    "nick": "nickaAWE234 asd",
                    "user": "user sF S",
                    "host": ""
                }
            ],
            [
                "nickaAWE234 asd!user sF S@HoST N",
                {
                    "nick": "nickaAWE234 asd",
                    "user": "user sF S",
                    "host": "HoST N"
                }
            ]
        ]

        for vector in vectors:
            buf, expected = vector
            got = irc_extract_sender(buf)
            assert(got == expected)

    async def test_start_n(self):
        servers = [
            {"domain": "a"},
            {"domain": "b"},
            {"domain": "c"},
            {"domain": "d"},
            {"domain": "e"},
        ]

        interface = None
        ircdns = await IRCDNS(
            i=interface,
            seed=b"1" + IRC_SEED,
            clsSess=MockIRCSession,
            clsChan=MockIRCChan,
            servers=servers,
            executor=executor,
            do_shuffle=False
        ).start()

        # Sanity checks on length.

        # Should continue.
        await ircdns.start_n(len(servers) - 1)
        assert(ircdns.p_sessions_next == len(servers) - 1)

        await ircdns.start_n(1)
        assert(ircdns.p_sessions_next == len(servers))

        #cd projects/p2pd/tests
        #  python -m unittest test_irc_dns.TestIRCDNS.test_start_n



        exception_thrown = 1
        try:
            await ircdns.start_n(1)
        except:
            exception_thrown = 1

        assert(exception_thrown)

        await ircdns.close()



        # Test partial start-continue
        ircdns = await IRCDNS(
            i=interface,
            seed=b"2" + IRC_SEED,
            clsSess=MockIRCSession,
            clsChan=MockIRCChan,
            servers=servers,
            executor=executor,
            do_shuffle=False
        ).start()

        await ircdns.start_n(2)
        assert(ircdns.p_sessions_next == 2)



        # Test making irc chan name
        dns_name = "p2pd_test"
        dns_tld = "test_tld"
        dns_val = "test val"
        await ircdns.pre_cache(dns_name, dns_tld)

        dns_hash = await ircdns.sessions[0].get_irc_chan_name(
            name=dns_name,
            tld=dns_tld,
            executor=executor
        )

        assert(irc_is_valid_chan_name(dns_hash))
        assert(len(dns_hash) <= 32)

        assert(await ircdns.get_server_len() == len(servers))
        assert(await ircdns.get_register_failure_max() == 2)

        assert(await ircdns.get_register_success_min() == 3)


        assert(await ircdns.get_register_success_max() == len(servers))


        assert(await ircdns.get_lookup_success_min() == 3)


        # Register, store, then get.
        ret, _ = await ircdns.name_register(dns_name, dns_tld)
        assert(len(ret))


        # Test store.
        await ircdns.store_value(dns_val, dns_name, dns_tld)
        otps = []
        sigs = []
        for i in range(0, len(servers)):
            test_hash = await ircdns.sessions[i].get_irc_chan_name(
                name=dns_name,
                tld=dns_tld
            )

            assert(test_hash in ircdns.sessions[i].chans)

            # Msg integrity is uniquely tied to channel integrity.
            topic_val = ircdns.sessions[i].chans[test_hash].pending_topic
            out = f_unpack_topic(
                test_hash,
                topic_val,
                ircdns.sessions[i]
            )

            # As a basic assumption these should all be different.
            # Time discards non-seconds so it may occur in the same 'tick'
            assert(out["time"] > 315360000)
            assert(dns_val in out["msg"])
            assert(out["otp"] not in otps)
            assert(out["sig"] not in sigs)
            otps.append(out["otp"])
            sigs.append(out["sig"])

        # Get results list.
        results, _ = await ircdns.n_name_lookups(
            await ircdns.get_lookup_success_min(),
            0,
            dns_name,
            dns_tld
        )


        best = await ircdns.n_more_or_best(results)

        # Check that best value is correct.
        highest = results[0]["time"]
        for r in results:
            if r["time"] > highest:
                highest = r["time"]

        assert(highest == best["time"])

        freshest = await ircdns.name_lookup(
            name=dns_name,
            tld=dns_tld
        )

        assert(best == freshest)

        await ircdns.close()

        # unpack

        #assert(ircdns.sessions[0].chans[dns_hash].pending_topic == dns_val)

        # assert len of user pass nick email ... etc

    async def test_with_some_failed_sessions(self):
        class MockIRCSession2(MockIRCSession):
            async def start(self, i):
                if self.db is not None:
                    last_started_key = self.db_key("last_started")
                    await self.db.put(last_started_key, time.time())


                if self.offset not in [1, 5]:
                    self.started.set_result(True)
                else:
                    raise Exception("Cannot start!")

        interface = None
        ircdns = await IRCDNS(
            i=interface,
            seed=b"3" + IRC_SEED,
            clsSess=MockIRCSession2,
            clsChan=MockIRCChan,
            servers=IRC_TEST_SERVERS_SEVEN,
            executor=executor,
            do_shuffle=False
        ).start()


        assert(await ircdns.get_server_len() == 7)
        assert(await ircdns.get_register_success_min() == 5)
        dns_name = "p2pd_test2"
        dns_tld = "test_tld2"
        dns_val = "test val2"
        ret, _ = await ircdns.name_register(dns_name, dns_tld)
        await ircdns.store_value(dns_val, dns_name, dns_tld)

        ret = await ircdns.name_lookup(dns_name, dns_tld)
        assert(dns_val in ret["msg"])
        await ircdns.close()

    async def test_register_partial_to_simulate_session_restart(self):
        """
        It should initially start enough sessions to pass the
        get_success_min check (p_session_next will point to len)
        but later when it calls start again it
        should return success that time indicating that servers have
        come back online. The results should show success for those previously
        down servers.
        """
        class MockIRCSession4(MockIRCSession):
            offset_count = {}
            async def start(self, i):
                if self.db is not None:
                    last_started_key = self.db_key("last_started")
                    await self.db.put(last_started_key, time.time())


                if self.offset not in self.offset_count:
                    self.offset_count[self.offset] = 0
                self.offset_count[self.offset] += 1
                

                # Simulate one server down.
                if self.offset not in [0, 1]:
                    self.started.set_result(True)
                else:
                    if self.offset_count[self.offset] > 1:
                        self.started.set_result(True)
                    else:
                        raise Exception("Start failure!")

            # Disable DB caching for this test.
            async def db_is_name_registered(self, name, tld, pw=""):
                return False

        interface = None
        ircdns = await IRCDNS(
            i=interface,
            seed=b"4" + IRC_SEED,
            clsSess=MockIRCSession4,
            clsChan=MockIRCChan,
            servers=IRC_TEST_SERVERS_SEVEN,
            executor=executor,
            do_shuffle=False
        ).start()

        await ircdns.start_n(len(IRC_TEST_SERVERS_SEVEN))
        assert(ircdns.p_sessions_next == len(IRC_TEST_SERVERS_SEVEN))
        ret, _ = await ircdns.name_register("test_name6", "test_tld6")
        for chan_info in ret:
            assert(chan_info["status"] == IRC_REGISTER_SUCCESS)

        await ircdns.close()

    async def test_successive_register(self):
        """
        The first register should not succeed on all servers (some will be down)
        while the second register should succeed to simulate the servers
        returning. One of the names will be unavailable just to mix things up.
        """
        class MockIRCSession5(MockIRCSession):
            offset_count = {}
            async def start(self, i):
                if self.db is not None:
                    last_started_key = self.db_key("last_started")
                    await self.db.put(last_started_key, time.time())


                if self.offset not in self.offset_count:
                    self.offset_count[self.offset] = 0
                self.offset_count[self.offset] += 1
                

                # Simulate one server down.
                if self.offset not in [0]:
                    self.started.set_result(True)
                else:
                    # Fail on start_n and start in do_register.
                    # Next register will succeed.
                    if self.offset_count[self.offset] > 2:
                        self.started.set_result(True)
                    else:
                        raise Exception("Start failure!")
                    
            # ... and simulate one server having a name conflict.
            async def is_chan_registered(self, chan_name):
                if self.offset in [1]:
                    return "someone_else"
                else:
                    return await super().is_chan_registered(chan_name)
                
            # Disable DB caching for this test.
            async def db_is_name_registered(self, name, tld, pw=""):
                return False
                
        interface = None
        ircdns = await IRCDNS(
            i=interface,
            seed=b"5" + IRC_SEED,
            clsSess=MockIRCSession5,
            clsChan=MockIRCChan,
            servers=IRC_TEST_SERVERS_SEVEN,
            executor=executor,
            do_shuffle=False
        ).start()

        dns_name = "dns_name8"; dns_tld = "dns_tld8"
        ret, _ = await ircdns.name_register(dns_name, dns_tld)
        assert(ret[0]["status"] == IRC_START_FAILURE)
        assert(ret[1]["status"] == IRC_REGISTER_FAILURE)
        assert(ret[2]["status"] == IRC_REGISTER_SUCCESS)

        ret, _ = await ircdns.name_register(dns_name, dns_tld)
        assert(ret[0]["status"] == IRC_REGISTER_SUCCESS)
        assert(ret[1]["status"] == IRC_REGISTER_FAILURE)
        assert(ret[2]["status"] == IRC_REGISTER_SUCCESS)
        await ircdns.close()

    # check partial availability of names (some are already taken)
    async def test_partial_availability_of_names(self):
        class MockIRCSession3(MockIRCSession):
            async def start(self, i):
                if self.db is not None:
                    last_started_key = self.db_key("last_started")
                    await self.db.put(last_started_key, time.time())


                # Simulate one server down.
                if self.offset not in [5]:
                    self.started.set_result(True)
                else:
                    raise Exception("Start failure!")

            # ... and simulate one server having a name conflict.
            async def is_chan_registered(self, chan_name):
                if self.offset in [2]:
                    return "someone_else"
                else:
                    return await super().is_chan_registered(chan_name)
                
            # Disable DB caching for this test.
            async def db_is_name_registered(self, name, tld, pw=""):
                return False

        interface = None
        ircdns = await IRCDNS(
            i=interface,
            seed=b"6" + IRC_SEED,
            clsSess=MockIRCSession3,
            clsChan=MockIRCChan,
            servers=IRC_TEST_SERVERS_SEVEN,
            executor=executor,
            do_shuffle=False
        ).start()

        dns_name = "p2pd_test3"
        dns_tld = "test_tld3"
        dns_val = "test val3"
        ret, _ = await ircdns.name_register(dns_name, dns_tld)
        assert(ret[2]["status"] == IRC_REGISTER_FAILURE)
        assert(ret[5]["status"] == IRC_START_FAILURE)
        assert(ret[0]["status"] == IRC_REGISTER_SUCCESS)
        await ircdns.store_value("initial val", dns_name, dns_tld)
        await ircdns.store_value(dns_val, dns_name, dns_tld)
        ret = await ircdns.name_lookup(dns_name, dns_tld)
        assert(dns_val in ret["msg"])
        await ircdns.close()

    async def test_to_check_db_integrity_multi_chan_reg(self):
        interface = None
        ircdns = await IRCDNS(
            i=interface,
            seed=b"7" + IRC_SEED,
            clsSess=MockIRCSession,
            clsChan=MockIRCChan,
            servers=IRC_TEST_SERVERS_SEVEN,
            executor=executor,
            do_shuffle=False
        ).start()

        ret, _ = await ircdns.name_register("test_name4", "tld4")
        ret, _ = await ircdns.name_register("test_name5", "tld5")

        # Get list of chans stored in first session.
        chan_list = await ircdns.sessions[0].db_load_chan_list()
        vectors = [
            ["test_name4", "tld4"],
            ["test_name5", "tld5"]
        ]

        # Should have found both dns names.
        for vector in vectors:
            dns = {
                "name": vector[0],
                "tld": vector[1],
                "pw": ""
            }

            found = False
            for chan_name in chan_list:
                chan_info_key = ircdns.sessions[0].db_key(f"chan/{chan_name}")
                chan_info = await ircdns.db.get(chan_info_key, {})
                if "dns" not in chan_info:
                    continue

                if chan_info["dns"] == dns:
                    found = True
                    break
            assert(found)


        await ircdns.close()

    async def test_irc_refresher(self):
        """
        We'll artificially set a particular chan to have a refresh time far in
        the past to force the refresh code to fire. The code that is fired to
        achieve refreshes will be monkey-patched to avoid network errors.
        Fixed structures will be stored in the DB to make the testing simpler.
        The refresh code is fairly straight forwards so easier to test.
        """

        ircdns = await IRCDNS(
            i=None,
            seed=b"8" + IRC_SEED,
            clsSess=MockIRCSession,
            clsChan=MockIRCChan,
            servers=IRC_TEST_SERVERS_SEVEN,
            executor=executor,
            do_shuffle=False
        ).start()
        await ircdns.start_n(len(IRC_TEST_SERVERS_SEVEN))

        chan_name = "expired_chan"
        chan_info = {
            "chan_name": chan_name,
            "last_refresh": time.time() - (365 * 24 * 60 * 60)
        }

        nick = "expired_nick"
        nick_info = {
            "nick": nick,
            "last_refresh": time.time() - (365 * 24 * 60 * 60)
        }

        db = ircdns.db

        # Store the above expired chan info in the db.
        for n in range(0, ircdns.p_sessions_next):
            s = ircdns.sessions[n]
            s.refresh_chan_fired = None
            s.refresh_nick_fired = None
            chan_list = await s.db_load_chan_list()
            chan_list.add(chan_name)
            
            # Simulate expired channel.
            key_name = s.db_key("chan_list")
            await db.put(key_name, chan_list)
            key_name = s.db_key(f"chan/{chan_name}")
            await db.put(key_name, chan_info)

            # Simulate expired nick.
            key_name = s.db_key("nick")
            await db.put(key_name, nick_info)

        # Skeleton functions just to know if they were triggered.
        async def refresh_chan(chan_name, session):
            session.refresh_chan_fired = chan_name
        async def refresh_nick(session):
            session.refresh_nick_fired = "1"

        # Patch refresher obj with skeletons above.
        refresher = IRCRefresher(ircdns)
        refresher.refresh_chan = refresh_chan
        refresher.refresh_nick = refresh_nick

        # Call refresher for first time.
        # It should run the skeleton refresh funcs.
        await refresher.refresher()

        # Check that refresh functions fired.
        for n in range(0, ircdns.p_sessions_next):
            s = ircdns.sessions[n]
            assert(s.refresh_chan_fired == chan_name)
            assert(s.refresh_nick_fired == "1")
            s.refresh_chan_fired = None
            s.refresh_nick_fired = None

        # Run refresh again.
        # It should do nothing this time.
        await refresher.refresher()

        # Now check refresh function WASNT fired.
        for n in range(0, ircdns.p_sessions_next):
            s = ircdns.sessions[n]
            assert(s.refresh_chan_fired == None)
            assert(s.refresh_nick_fired == None)

        await ircdns.close()
    
    # python -m unittest test_irc_dns.TestIRCDNS.test_irc_refresher_does_register
    async def test_irc_refresher_does_register(self):
        class MockIRCSession6(MockIRCSession):
            offset_count = {}
            async def start(self, i):
                if self.db is not None:
                    last_started_key = self.db_key("last_started")
                    await self.db.put(last_started_key, time.time())


                if self.offset not in self.offset_count:
                    self.offset_count[self.offset] = 0
                self.offset_count[self.offset] += 1
                

                # Simulate one server down.
                if self.offset not in [0]:
                    self.started.set_result(True)
                else:
                    # Fail on start_n and start in do_register.
                    # Next register will succeed.
                    if self.offset_count[self.offset] > 2:
                        self.started.set_result(True)
                    else:
                        raise Exception("Start failure!")
                
            # Disable DB caching for this test.
            async def db_is_name_registered(self, name, tld, pw=""):
                return False
            
        ircdns = await IRCDNS(
            i=None,
            seed=b"9" + IRC_SEED,
            clsSess=MockIRCSession6,
            clsChan=MockIRCChan,
            servers=IRC_TEST_SERVERS_SEVEN,
            executor=executor,
            do_shuffle=False
        ).start()

        dns_name = "dns_name9"; dns_tld = "dns_tld9"
        ret, _ = await ircdns.name_register(dns_name, dns_tld)
        assert(ret[0]["status"] == IRC_START_FAILURE)
        assert(ret[1]["status"] == IRC_REGISTER_SUCCESS)
        dns = ret[0]["dns"]

        refresher = IRCRefresher(ircdns)
        refresher.register_chan = lambda x: None
        await refresher.refresher(ignore_failure=True)

        # Check that register was ran for the channel in refresh.
        register_success = False
        chan_list = await ircdns.sessions[0].db_load_chan_list()
        for chan_name in chan_list:
            chan_info_key = ircdns.sessions[0].db_key(f"chan/{chan_name}")
            chan_info = await ircdns.db.get(chan_info_key, {})
            if "dns" not in chan_info:
                continue

            if chan_info["dns"] == dns:
                if chan_info["status"] == IRC_REGISTER_SUCCESS:
                    register_success = True
        assert(register_success)

        await ircdns.close()

    async def test_nick_details_save(self):
        ircdns = await IRCDNS(
            i=None,
            seed=b"10" + IRC_SEED,
            clsSess=MockIRCSession,
            clsChan=MockIRCChan,
            servers=IRC_TEST_SERVERS_SEVEN,
            executor=executor,
            do_shuffle=False
        ).start()

        # Start only a single session at offset 0.
        await ircdns.start_n(1)

        # Attempt to fetch sessions nick details.
        nick_key = ircdns.sessions[0].db_key("nick")
        nick_info = await ircdns.db.get(nick_key, {})
        vectors = ["domain", "nick", "username", "user_pass"]
        vectors += ["email", "last_refresh"]
        for vector in vectors:
            assert(vector in nick_info)

        # Cleanup.
        await ircdns.close()

    async def test_irc_dns_real_world(self):
        return
        interface = await Interface()
        seed = b_sha3_256(b"some secret seed")
        ircdns = await IRCDNS(
            i=interface,
            seed=seed,
            servers=IRC_SERVERS
        ).start()
        refresher = IRCRefresher(ircdns)

        # Register a new name from scratch.
        name_info = ["muh awesome name", "node"]
        await ircdns.name_register(*name_info)

        # Do two different write/reads.
        for _ in range(0, 2):
            # Store value in entry.
            name_val  = rand_plain(10)
            await ircdns.store_value(*[name_val] + name_info)

            # Lookup its value and check results.
            ret = await ircdns.name_lookup(*name_info)
            assert(to_b(ret["msg"]) == to_b(name_val))

        # Test refresher also doesn't crash.
        await refresher.refresher()

        # Cleanup the dns manager.
        await ircdns.close()

    async def test_irc_servers_work(self):
        return
        dns_value = "Test dns val."
        dns_name = "testing_dns_name"
        dns_tld = "testing"
        dns_pw = ""
        executor = ProcessPoolExecutor()
        server_list = IRC_SERVERS

        seed = b"test_seed2" * 20
        i = await Interface().start()
        ircdns = await IRCDNS(
            i,
            seed,
            server_list,
            executor,
            do_shuffle=False
        ).start()

        


        print("If start")
        print(i)

        for offset, s in enumerate(server_list[3:]):
            print(f"testing {s} : {offset}")

            ses = IRCSession(s, seed)

            try:
                await ses.start(i)
                print("start success")
            except:
                print(f"start failed for {s}")
                what_exception()


            chan_name = await ses.get_irc_chan_name(
                name=dns_name,
                tld=dns_tld,
                pw=dns_pw,
                executor=executor
            )

            # Test chan create.
            print("trying to check if chan is registered.")
            ret = await ses.is_chan_registered(chan_name)
            if ret:
                print(f"{chan_name} registered, not registering")

                # Check channel owner returned is correct.
                assert(ret == ses.nick)

                # 'load' chan instead.
                irc_chan = IRCChan(chan_name, ses)
                ses.chans[chan_name] = irc_chan
                print(irc_chan.chan_pass)
            else:
                print(f"{chan_name} not registered, attempting to...")
                await ses.register_chan(chan_name)
                ret = await ses.is_chan_registered(chan_name)
                if ret:
                    print("success")
                else:
                    print("failure")
                    exit()

            # Test set topic.
            chan_topic = to_s(rand_plain(8))
            chan_topic, _ = await f_pack_topic(
                value=dns_value,
                name=dns_name,
                tld=dns_tld,
                pw=dns_pw,
                ses=ses,
                clsChan=IRCChan,
                executor=executor
            )

            print(f"trying to store {chan_topic}")

            #await irc_dns.chans[chan_name].get_ops()
            #print("get ops done")
            await ses.chans[chan_name].set_topic(chan_topic)
            print("set topic done")

            # Potential race condition between getting new chan.
            await asyncio.sleep(4)

            outside_user = IRCSession(s, seed + "2")
            try:
                await outside_user.start(i)
                print("start success")
            except:
                print(f"start failed for outside user")
                what_exception()

            out = await outside_user.get_chan_topic(chan_name)
            if out != chan_topic:
                print(f"got {out} for chan topic and not {chan_topic}")
                exit()
            else:
                print("success")

            # Test decode of encoded chan topic.
            unpack_topic = f_unpack_topic(
                chan_name,
                chan_topic,
                ses
            )

            print(unpack_topic)

            print("unpacked topic = ")
            assert(to_b(unpack_topic["msg"]) == to_b(dns_value))

            # Cleanup.
            await outside_user.close()
            await ses.close()
            input("Press enter to test next server.")
            input()

    async def test_find_more_servers(self):
        pass

if __name__ == '__main__':
    executor = ProcessPoolExecutor()
    main()
    executor.shutdown(wait=False)

"""

"""