"""
    async def test_irc_dns():
        """
        msg = ":ChanServ!services@services.xxxchatters.com NOTICE client_dev_nick1sZU8um :Channel \x02#qfATvV8F\x02 registered under your account: client_dev_nick1sZU8um\r\n:ChanServ!services@services.xxxchatters.com MODE #qfATvV8F +rq client_dev_nick1sZU8um\r\n"
        out = extract_irc_msgs(msg)
        print(out)
        print(out[0][0].suffix)

        
        return
        """

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


        """
        await irc_dns.con.send(
            IRCMsg(
                cmd="LIST",
                param="*"
            ).pack()

        )

        while 1:
            await asyncio.sleep(1)
        """


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