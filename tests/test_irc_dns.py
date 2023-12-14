"""
    async def test_irc_dns():
        


        chan_topic = "this_is_test_chan_topic"
        chan_name = "#test_chan_name323" + IRC_PREFIX
        server_list = IRC_SERVERS

        seed = "test_seed" * 20
        i = await Interface().start()



        print("If start")
        print(i)

        for offset, s in enumerate(server_list[1:]):
            print(f"testing {s} : {offset}")

            irc_dns = IRCSession(s, seed)

            try:
                await irc_dns.start(i)
                print("start success")
            except:
                print(f"start failed for {s}")
                what_exception()

            #await irc_dns.get_chan_reg_syntax()
            #await asyncio.sleep(10)
            #exit()

            # Test chan create.
            print("trying to check if chan is registered.")
            ret = await irc_dns.is_chan_registered(chan_name)
            if ret:
                print(f"{chan_name} registered, not registering")

                # 'load' chan instead.
                irc_chan = IRCChan(chan_name, irc_dns)
                irc_dns.chans[chan_name] = irc_chan
                print(irc_chan.chan_pass) # S:1f(.9i{e@3$Fkxq^f{JW,>sVQi?Q\
            else:
                print(f"{chan_name} not registered, attempting to...")
                await irc_dns.register_channel(chan_name)
                ret = await irc_dns.is_chan_registered(chan_name)
                if ret:
                    print("success")
                else:
                    print("failure")
                    exit()

            # Test set topic.
            chan_topic = to_s(rand_plain(8))
            #await irc_dns.chans[chan_name].get_ops()
            #print("get ops done")
            await irc_dns.chans[chan_name].set_topic(chan_topic)
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

            

            # Cleanup.
            await outside_user.close()
            await irc_dns.close()
            input("Press enter to test next server.")
            input()
            


        return


    
        await irc_dns.con.send(
            IRCMsg(
                cmd="LIST",
                param="*"
            ).pack()

        )

        while 1:
            await asyncio.sleep(1)
        


        #print(await irc_dns.register_channel("#test_chan_name123"))
        #await asyncio.sleep(2)
        #print(await irc_dns.register_channel("#test_chan_name222"))

        chan_name = "#test_chan_name123"
        irc_chan = IRCChan(chan_name, irc_dns)
        irc_dns.chans[chan_name] = irc_chan

        print(irc_dns.chans)
        await irc_dns.chans[chan_name].get_ops()
        print("got ops")

        o = await irc_dns.chans[chan_name].set_topic("test topic to set.")
        print(o)
        print("topic set")

        chan_topic = await irc_dns.get_chan_topic(chan_name)
        print("got chan topic = ")
        print(chan_topic)

        await irc_dns.close()
        return

        while 1:
            await asyncio.sleep(1)


        return



        
        tasks = []
        for server in IRC_SERVERS1:
            task = async_wrap_errors(IRCDNS(server).start(i))
            tasks.append(task)

        out = await asyncio.gather(*tasks)
        print(out)
        out = strip_none(out)
        print(out)
        return
        

        
        for server in IRC_SERVERS1:
            out = await async_wrap_errors(
                IRCDNS(server).start(i),
                timeout=20
            )
            print(out)
"""

from p2pd.test_init import *
from p2pd import *

IRC_SEED = "123" * 30
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


class TestIRCDNS(unittest.IsolatedAsyncioTestCase):
    async def test_proto_ping(self):
        msg = IRCMsg(cmd="PING", param="31337")
        resp = IRC_S.proto(msg)
        assert(resp.pack() == b"PONG 31337\r\n")

        msg = IRCMsg(cmd="PING", suffix="31337")
        resp = IRC_S.proto(msg)
        assert(resp.pack() == b"PONG :31337\r\n")

    async def test_proto_ctcp_version(self):
        msg = IRCMsg(
            cmd="PRIVMSG",
            prefix="user!ident@host",
            suffix="\x01VERSION\x01"
        )

        resp = IRC_S.proto(msg)
        expected = to_b(f"PRIVMSG user :\x01VERSION {IRC_VERSION}\x01\r\n")
        assert(resp.pack() == expected)

    async def test_proto_is_chan_reg(self):
        chan_name = "#test-wrwerEWER342"
        vectors = [
            [f"channel {chan_name} isn't", False],
            [f"channel {chan_name} is not", False],
            [f"information for {chan_name}", True],
            [f"information on {chan_name}", True],
            [f"channel {chan_name} is registered", True]
        ]

        for vector in vectors:
            IRC_S.chan_infos[chan_name] = asyncio.Future()

            status, expected = vector
            msg = IRCMsg(
                cmd="NOTICE",
                param="your_nick",
                suffix=status
            )

            IRC_S.proto(msg)
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
        IRC_S.proto(msg)
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
        class MockIRCChan(IRCChan):
            async def set_topic(self, topic):
                self.pending_topic = topic

        class MockIRCSession(IRCSession):
            """
            def __init__(self, server_info, seed):
                super().__init__(server_info, seed)
            """

            async def start(self):
                self.started.set_result(True)

            async def is_chan_registered(self, chan_name):
                return chan_name in self.chan_registered
            
            async def register_chan(self, chan_name):
                self.chan_registered[chan_name] = True

            async def get_chan_topic(self, chan_name):
                return self.chans[chan_name].pending_topic

            """
            async def get_irc_chan_name(self, name, tld, pw=""):
                # Domain names are unique per server.
                msg = to_b(f"{self.irc_server} {pw} {name} {tld}")
                return "#" + to_s(
                    # The result is encoded using A-Z0-9 for chan names.
                    encodebytes(
                        # Multiple hash functions make collisions harder to find.
                        # As a value will need to work for both functions.
                        hash160(
                            hashlib.sha256(
                                msg
                            ).digest()
                        ),
                        charset=B36_CHARSET
                    )
                )[:31].lower()
            """

        executor = ProcessPoolExecutor(max_workers=8)
        servers = [
            {"domain": "a"},
            {"domain": "b"},
            {"domain": "c"},
            {"domain": "d"},
            {"domain": "e"},
        ]


        interface = None
        ircdns = IRCDNS(
            i=interface,
            seed=IRC_SEED,
            clsSess=MockIRCSession,
            clsChan=MockIRCChan,
            servers=servers,
            executor=executor,
            do_shuffle=False
        )

        # Should continue.
        await ircdns.start_n(len(servers) - 1)
        assert(ircdns.p_sessions_next == len(servers) - 1)

        await ircdns.start_n(1)
        assert(ircdns.p_sessions_next == len(servers))

        exception_thrown = 1
        try:
            await ircdns.start_n(1)
        except:
            exception_thrown = 1

        assert(exception_thrown)

        # Test partial start-continue
        ircdns = IRCDNS(
            i=interface,
            seed=IRC_SEED,
            clsSess=MockIRCSession,
            clsChan=MockIRCChan,
            servers=servers,
            executor=executor,
            do_shuffle=False
        )

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

        # Register, store, then get.
        ret = await ircdns.name_register(dns_name, dns_tld)
        assert(ret)

        # Test store.
        await ircdns.store_value(dns_val, dns_name, dns_tld)
        for i in range(0, len(servers)):
            test_hash = await ircdns.sessions[i].get_irc_chan_name(
                name=dns_name,
                tld=dns_tld
            )

            assert(test_hash in ircdns.sessions[i].chans)

        topic_val = ircdns.sessions[0].chans[dns_hash].pending_topic
        out = ircdns.unpack_topic_value(topic_val)

        # Get results list.
        results, _ = await ircdns.n_name_lookups(
            ircdns.get_success_min(),
            0,
            dns_name,
            dns_tld
        )
        best = ircdns.n_more_or_best(results)
        
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

        # unpack

        #assert(ircdns.sessions[0].chans[dns_hash].pending_topic == dns_val)

if __name__ == '__main__':
    main()

"""

"""