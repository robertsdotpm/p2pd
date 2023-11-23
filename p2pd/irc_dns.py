"""
- Firewalls for IRC servers silently drop packets if you
make successive connections too closely.



I dont think I can test the code on my p2pd server as it
actually is running proxies.

not quite sure how to determine a success response for a nick?
maybe the right approach is to then try a operation that needs those perms?


['irc.libera.chat', 'irc.esper.net']
"irc.darkmyst.org"
'irc.oftc.net',
'irc.euirc.net', 'irc.xxxchatters.com', 'irc.swiftirc.net']
###['irc.ouch.chat', 'irc.spotchat.org', 'irc.scoutlink.net']

filtered:
['irc.oftc.net', 'irc.euirc.net', 'irc.xxxchatters.com', 'irc.swiftirc.net', 'irc.darkmyst.org']

['irc.chatjunkies.org', 'irc.dosers.net', 'irc.entropynet.net',  'irc.liberta.casa']

'irc.financialchat.com', 'irc.irc2.hu', 'irc.phat-net.de', 'irc.slacknet.org', 'irc.tweakers.net'

IP6:

['irc.oftc.net', 'irc.euirc.net', 'irc.swiftirc.net', 'irc.darkmyst.org', 'irc.entropynet.net', 'irc.liberta.casa', 'irc.phat-net.de', 'irc.slacknet.org', 'irc.tweakers.net']


SERVERS = [
    {
        'domain': 'irc.oftc.net'
        'afs': [IP4, IP6]
    },
    {
        'domain': 'irc.euirc.net',
        'afs': [IP4, IP6]
    },
    {
        'domain': 'irc.xxxchatters.com',
        'afs': [IP4]
    },
    {
        'domain': 'irc.swiftirc.net',
        'afs': [IP4, IP6]
    },
    {
        'domain': 'irc.darkmyst.org',
        'afs': [IP4, IP6]
    },
    {
        'domain': 'irc.chatjunkies.org',
        'afs': [IP4]
    },
    {
        'domain': 'irc.dosers.net',
        'afs': [IP4]
    },
    {
        'domain': 'irc.entropynet.net',
        'afs': [IP4, IP6]
    },
    {
        'domain': 'irc.liberta.casa',
        'afs': [IP4, IP6]
    },
        {
        'domain': 'irc.financialchat.com',
        'afs': [IP4]
    },
    {
        'domain': 'irc.irc2.hu',
        'afs': [IP4]
    },
    {
        'domain': 'irc.phat-net.de',
        'afs': [IP4, IP6]
    },
    {
        'domain': 'irc.slacknet.org',
        'afs': [IP4, IP6]
    },
        {
        'domain': 'irc.tweakers.net',
        'afs': [IP4, IP6]
    },
]

14 servers to start with. not bad. this should work.

these results are about what i calculated. so maybe its not too bad.

a more advanced scanner that can account for the 30 min wait time for nick and chan
registration is likely to have more results
"""

import asyncio
import re
from .utils import *
from .address import *
from .interface import *
from .base_stream import *

IRC_AF = IP6
IRC_HOST = "irc.darkmyst.org" # irc.darkmyst.org
IRC_PORT = 6697
IRC_CONF = dict_child({
    "use_ssl": 1,
    "ssl_handshake": 8,
    "con_timeout": 4,
}, NET_CONF)

IRC_NICK = "client_dev_nick1" + to_s(rand_plain(8))
IRC_USERNAME = "client_dev_user1" + to_s(rand_plain(8))
IRC_REALNAME = "matthew" + to_s(rand_plain(8))
IRC_EMAIL = "test_irc" + to_s(rand_plain(8)) + "@p2pd.net"
IRC_PASS = to_s(file_get_contents("p2pd/irc_pass.txt"))
IRC_CHAN = f"#{to_s(rand_plain(8))}"
IRC_HOSTNAME = to_s(rand_plain(8))

class IRCMsg():
    def __init__(self, prefix=None, cmd=None, param=None, suffix=None):
        self.prefix = prefix
        self.cmd = cmd
        self.param = param
        self.suffix = suffix

    def pack(self):
        param = prefix = suffix = ""
        if self.prefix:
            prefix = f":{self.prefix} "
        
        if self.suffix:
            suffix = f" :{self.suffix}"

        if self.param:
            param = self.param

        return to_b(f"{prefix}{self.cmd} {param}{suffix}\r\n")

"""
TCP is stream-oriented and portions of IRC protocol messages
may be received. This code handles finding valid IRC messages and
truncating the recv buffer once extracted.
"""
def extract_irc_msgs(buf):
    #     optional                                       optional
    #     :prefix            CMD           param...      :suffix 
    p = "(?:[:]([^ :]+?) )?([A-Z0-9]+) (?:([^\r\:]+?) ?)?(?:[:]([^\r]+))?\r\n"
    p = re.compile(p)

    # Loop over all protocol messages in buf.
    # Truncate buf as messages are extracted.
    msgs = []
    offset = None
    while 1:
        # No matches found yet.
        # Buffer contains a partial response or its empty.
        match = p.search(buf)
        if match is None:
            break

        # Extract matched message.
        msg = IRCMsg(*list(match.groups()))
        msgs.append(msg)

        # Get the offset of the match end.
        # Truncate buf as messages are extracted.
        offset = match.end()
        if offset < len(buf):
            buf = buf[offset:]
        else:
            buf = ""

    return msgs, buf

class IRCDNS():
    def __init__(self, irc_server):
        self.con = None
        self.recv_buf = ""
        self.get_motd = asyncio.Future()
        self.register_status = asyncio.Future()
        self.irc_server = irc_server

    async def start(self, i):
        dest = await Address(self.irc_server, IRC_PORT, i.route(IRC_AF))
        nick_msg = IRCMsg(cmd="NICK", param=IRC_NICK)
        user_msg = IRCMsg(
            cmd="USER",
            param=f"{IRC_USERNAME} {IRC_HOSTNAME} *",
            suffix=f"{IRC_REALNAME}"
        )

        route = await i.route(IRC_AF).bind()
        self.con = await pipe_open(
            TCP,
            route,
            dest,
            msg_cb=self.msg_cb,
            conf=IRC_CONF
        )

        # Send data and allow for time to receive them.
        nick_buf = nick_msg.pack()
        await self.con.send(nick_buf)   

        user_buf = user_msg.pack()
        await self.con.send(user_buf)
        await asyncio.sleep(0)

        # Wait for message of the day.
        await asyncio.wait_for(
            self.get_motd, 30
        )

        # Attempt to register the nick at the server.
        # See if the server requires confirmation.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="NickServ",
                suffix=f"REGISTER {IRC_PASS} {IRC_EMAIL}"
            ).pack()
        )
        await asyncio.sleep(2)


        # Join channel.
        await self.con.send(
            IRCMsg(
                cmd="JOIN",
                param=f"{IRC_CHAN}",
            ).pack()
        )

        # register channel.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"REGISTER {IRC_CHAN}"
            ).pack()
        )

        # register channel.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"REGISTER {IRC_CHAN} sdv234iwsk13g8q__wlsdf"
            ).pack()
        )

        # register channel.
        await self.con.send(
            IRCMsg(
                cmd="PRIVMSG",
                param="ChanServ",
                suffix=f"REGISTER {IRC_CHAN} sdv234iwsk13g8q__wlsdf desc"
            ).pack()
        )

        # Wait for message of the day.
        await asyncio.wait_for(
            self.register_status, 10
        )

        await self.con.send(IRCMsg(cmd="QUIT").pack())
        await self.con.close()
        return self.irc_server

    async def msg_cb(self, msg, client_tup, pipe):
        pos_chan_msgs = [
            "registered under",
            "is now registered",
            "successfully registered",
        ]

        neg_chan_msgs = [
            "not complete registration",
            "following link",
            "link expires",
            "address is not confirmed"
        ]

        try:
            # Keep a buffer of potential protocol messages.
            # These may be partial in the case of TCP.
            self.recv_buf += to_s(msg)
            msgs, new_buf = extract_irc_msgs(self.recv_buf)
            self.recv_buf = new_buf

            # Disable chan success in some cases.
            skip_register = False
            for msg in msgs:
                if isinstance(msg.suffix, str):
                    for chan_fail in neg_chan_msgs:
                        if chan_fail in msg.suffix:
                            skip_register = True
                            break

            # Loop over the IRC protocol messages.
            # Process the minimal functions we understand.
            for msg in msgs:
                # End of motd.
                if msg.cmd in ["376", "411"]:
                    self.get_motd.set_result(True)

                # Process ping.
                if msg.cmd == "PING":
                    pong = IRCMsg(
                        cmd="PONG",
                        suffix=msg.suffix,
                    )

                    await self.con.send(pong.pack())

                # Channel registered successfully.
                if isinstance(msg.suffix, str):
                    if skip_register == False:
                        for chan_success in pos_chan_msgs:
                            if chan_success in msg.suffix:
                                self.register_status.set_result(True)
        except:
            log_exception()

        

if __name__ == '__main__':
    IRC_SERVERS1 = [
        "irc.libera.chat",
        "irc.oftc.net",
        "irc.uni-erlangen.de",
        "irc.undernet.org",
        "irc.uworld.se",
        "irc.efnet.nl",
        "irc.freenode.net",
        "irc.quakenet.org",
        "irc.hackint.org",
        "irc.dal.net",
        "irc.chathispano.com",
        "irc.p2p-network.net",
        "irc.kampungchat.org",
        "irc.simosnap.com",
        "irc.hybridirc.com",
        "irc.explosionirc.net",
        "irc.gamesurge.net",
        "irc.snoonet.org",
        "irc.link-net.org",
        "irc.esper.net",
        "irc.abjects.net",
        "irc.synirc.net",
        "irc.europnet.org",
        "irc.konnectchatirc.net",
        "irc.oltreirc.eu",
        "irc.irchighway.net",
        "irc.irc-nerds.net",
        "irc.scenep2p.net",
        "irc.orixon.org",
        "irc.coders-irc.net",
        "irc.openjoke.org",
        "irc.digitalirc.org",
        "irc.darkscience.net",
        "irc.tilde.chat",
        "irc.geeknode.org",
        "irc.slashnet.org",
        "irc.sohbet.net",
        "irc.w3.org",
        "irc.IRCGate.it",
        "irc.chaat.fr",
        "irc.rootworld.net",
        "irc.darkfasel.net",
        "irc.freeunibg.eu",
        "irc.euirc.net",
        "irc.geekshed.net",
        "irc.globalirc.it",
        "irc.chatbg.info",
        "irc.furnet.org",
        "irc2.irccloud.com",
        "irc.xxxchatters.com",
        "irc.bol-chat.com",
        "irc.sorcery.net",
        "irc.dejatoons.net",
        "irc.technet.chat",
        "irc.kalbim.net",
        "irc.ptnet.org",
        "irc1.ptirc.org",
        "irc.skychatz.org",
        "irc.axon.pw",
        "irc.tamarou.com",
        "irc.mindforge.org",
        "irc.abandoned-irc.net",
        "irc.epiknet.org",
        "irc.allnetwork.org",
        "irc1.net-tchat.fr",
        "irc.swiftirc.net",
        "irc.afternet.org",
        "irc2.chattersnet.nl",
        "irc.allnightcafe.com",
        "irc.evilnet.org",
        "irc.rezosup.org",
        "irc.recycled-irc.net",
        "irc2.acc.umu.se",
        "irc.mibbit.net",
        "irc.pirc.pl",
        "irc.atrum.org",
        "irc.chatlounge.net",
        "irc.librairc.net",
        "irc.lunarirc.net",
        "irc.bigua.org",
        "irc.smurfnet.ch",
        "irc.ouch.chat",
        "irc.lewdchat.com",
        "irc.deutscher-chat.de",
        "irc.scuttled.net",
        "irc.chat.com.tr",
        "irc.spotchat.org",
        "irc.gigairc.net",
        "irc.darkworld.network",
        "irc.zenet.org",
        "irc.scoutlink.net",
        "irc.do-dear.com",
        "irc.luatic.net",
        "irc.roircop.info",
        "irc.forumcerdas.net",
        "irc.darkmyst.org"
    ]

    #IRC_SERVERS1 = ["irc.darkmyst.org"]

    # Taken from hexchat
    # Lets see what happens.
    IRC_SERVERS1 = [
        "pirc.pl",
        "newserver",
        "irc.2600.net",
        "global.acn.gr",
        "irc.afternet.org",
        "irc.data.lt",
        "irc.omicron.lt",
        "irc.vub.lt",
        "irc.anthrochat.net",
        "arcnet-irc.org",
        "irc.austnet.org",
        "irc.azzurra.org",
        "irc.canternet.org",
        "irc.chat4all.org",
        "irc.chatjunkies.org",
        "irc.unibg.net",
        "irc.chatpat.bg",
        "irc.chatspike.net",
        "irc.dairc.net",
        "us.dal.net",
        "irc.darkmyst.org",
        "irc.darkscience.net",
        "irc.drk.sc",
        "irc.darkscience.ws",
        "irc.d-t-net.de",
        "irc.digitalirc.org",
        "irc.dosers.net",
        "irc.choopa.net",
        "efnet.port80.se",
        "irc.underworld.no",
        "efnet.deic.eu",
        "irc.enterthegame.com",
        "irc.entropynet.net",
        "irc.esper.net",
        "irc.euirc.net",
        "irc.europnet.org",
        "irc.fdfnet.net",
        "irc.gamesurge.net",
        "irc.geekshed.net",
        "irc.german-elite.net",
        "irc.gimp.org",
        "irc.gnome.org",
        "irc.globalgamers.net",
        "irc.hackint.org",
        "irc.eu.hackint.org",
        "irc.hashmark.net",
        "irc.icq-chat.com",
        "irc.interlinked.me",
        "irc.irc4fun.net",
        "irc.irchighway.net",
        "open.ircnet.net",
        "irc.irctoo.net",
        "irc.kbfail.net",
        "irc.libera.chat",
        "irc.liberta.casa",
        "irc.librairc.net",
        "irc.link-net.org",
        "irc.mindforge.org",
        "irc.mixxnet.net",
        "irc.oceanius.com",
        "irc.oftc.net",
        "irc.othernet.org",
        "irc.oz.org",
        "irc.krstarica.com",
        "irc.pirc.pl",
        "irc.ptnet.org",
        "uevora.ptnet.org",
        "claranet.ptnet.org",
        "sonaquela.ptnet.org",
        "uc.ptnet.org",
        "ipg.ptnet.org",
        "irc.quakenet.org",
        "irc.rizon.net",
        "irc.tomsk.net",
        "irc.run.net",
        "irc.ru",
        "irc.lucky.net",
        "irc.serenity-irc.net",
        "irc.simosnap.com",
        "irc.slashnet.org",
        "irc.snoonet.org",
        "irc.sohbet.net",
        "irc.sorcery.net",
        "irc.spotchat.org",
        "irc.station51.net",
        "irc.stormbit.net",
        "irc.swiftirc.net",
        "irc.synirc.net",
        "irc.techtronix.net",
        "irc.tilde.chat",
        "irc.servx.org",
        "i.valware.uk",
        "irc.tripsit.me",
        "newirc.tripsit.me",
        "coconut.tripsit.me",
        "innsbruck.tripsit.me",
        "us.undernet.org",
        "irc.xertion.org"
    ]

    # These servers are taken from mirc.
    IRC_SERVERS1 = ['irc.dal.net', 'irc.efnet.org', 'open.ircnet.net', 'irc.libera.chat', 'irc.quakenet.org', 'irc.rizon.net', 'irc.snoonet.org', 'irc.swiftirc.net', 'irc.undernet.org', 'irc.scuttled.net', 'irc.abjects.net', 'irc.afternet.org', 'irc.data.lt', 'irc.allnetwork.org', 'irc.alphachat.net', 'irc.atrum.org', 'irc.austnet.org', 'irc.axon.pw', 'irc.ayochat.or.id', 'irc.azzurra.org', 'irc.beyondirc.net', 'irc.bolchat.com', 'ssl.bongster.de', 'irc.brasirc.com.br', 'irc.canternet.org', 'irc.chat4all.org', 'irc.chatspike.net', 'irc.chatzona.org', 'irc.cncirc.net', 'irc.coolsmile.net', 'irc.darenet.org', 'irc.d-t-net.de', 'irc.darkfasel.net', 'irc.darkmyst.org', 'irc.darkscience.net', 'irc.darkworld.network', 'irc.dejatoons.net', 'irc.desirenet.org', 'irc.ecnet.org', 'irc.epiknet.org', 'irc.esper.net', 'irc.euirc.net', 'irc.europnet.org', 'irc.evolu.net', 'irc.explosionirc.net', 'irc.fdfnet.net', 'irc.fef.net', 'irc.financialchat.com', 'irc.forestnet.org', 'irc.FreeUniBG.eu', 'irc.gamesurge.net', 'irc.geeknode.org', 'irc.geekshed.net', 'irc.german-elite.net', 'irc.gigairc.net', 'irc.gimp.org', 'irc.globalgamers.net', 'irc.goodchatting.com', 'irc.hackint.org', 'irc.hybridirc.com', 'irc.icq-chat.com', 'irc.immortal-anime.net', 'irc.indymedia.org', 'irc.irc-hispano.org', 'irc.irc2.hu', 'irc.irc4fun.net', 'irc.ircgate.it', 'irc.irchighway.net', 'irc.ircsource.net', 'irc.irctoo.net', 'irc.ircube.org', 'irc.ircworld.org', 'irc.irdsi.net', 'irc.kampungchat.org', 'irc.knightirc.net', 'irc.krey.net', 'irc.krono.net', 'irc.librairc.net', 'irc.lichtsnel.nl', 'irc.link-net.be', 'irc.luatic.net', 'irc.maddshark.net', 'irc.magicstar.net', 'irc.perl.org', 'irc.mibbit.net', 'irc.mindforge.org', 'irc.nationchat.org', 'irc.nightstar.net', 'irc.nullirc.net', 'irc.oftc.net', 'irc.oltreirc.net', 'irc.openjoke.org', 'irc.lt-tech.org', 'irc.orixon.org', 'irc.oz.org', 'irc.p2p-network.net', 'irc.phat-net.de', 'irc.krstarica.com', 'irc.pirc.pl', 'irc.ptnet.org', 'irc.recycled-irc.net', 'irc.retroit.org', 'irc.rezosup.org', 'irc.rusnet.org.ru', 'irc.scarynet.org', 'irc.serenity-irc.net', 'irc.shadowfire.org', 'irc.shadowworld.net', 'irc.simosnap.com', 'irc.SkyChatz.org', 'irc.skyrock.net', 'irc.slacknet.org', 'irc.slashnet.org', 'irc.smurfnet.ch', 'irc.sorcery.net', 'irc.spotchat.org', 'irc.st-city.net', 'irc.starlink-irc.org', 'irc.starlink.org', 'irc.staynet.org', 'irc.stormbit.net', 'irc.synirc.net', 'irc.technet.chat', 'irc.tilde.chat', 'irc.tweakers.net', 'irc.undermind.net', 'irc.wenet.ru', 'irc.whatnet.org', 'irc.wixchat.org', 'irc.worldirc.org', 'irc.xertion.org', 'irc.xevion.net']


    IRC_SERVERS1 = ['irc.oftc.net', 'irc.euirc.net', 'irc.xxxchatters.com', 'irc.swiftirc.net', 'irc.darkmyst.org', 'irc.chatjunkies.org', 'irc.dosers.net', 'irc.entropynet.net',  'irc.liberta.casa', 'irc.financialchat.com', 'irc.irc2.hu', 'irc.phat-net.de', 'irc.slacknet.org', 'irc.tweakers.net']

    async def test_irc_dns():
        """
        msg = ":ChanServ!services@services.xxxchatters.com NOTICE client_dev_nick1sZU8um :Channel \x02#qfATvV8F\x02 registered under your account: client_dev_nick1sZU8um\r\n:ChanServ!services@services.xxxchatters.com MODE #qfATvV8F +rq client_dev_nick1sZU8um\r\n"
        out = extract_irc_msgs(msg)
        print(out)
        print(out[0][0].suffix)

        
        return
        """


        i = await Interface().start()

        print("If start")
        print(i)

        
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


    async_test(test_irc_dns)