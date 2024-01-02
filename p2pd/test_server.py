from .net import *

"""
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
"""

irc_servers = [
    {
        'domain': 'irc.oftc.net',
        'afs': [IP4, IP6],

        # 20 jul 2002
        "creation": 1027087200
    },
    {
        'domain': 'irc.euirc.net',
        'afs': [IP4, IP6],


        # 19 sep 2000
        "creation": 969282000
    },
    {
        'domain': 'irc.xxxchatters.com',
        'afs': [IP4],

        # 9 march 2007
        'creation': 1173358800
    },
    {
        'domain': 'irc.swiftirc.net',
        'afs': [IP4, IP6],

        # 10 march 2007
        'creation': 1173445200
    },
    {
        'domain': 'irc.darkmyst.org',
        'afs': [IP4, IP6],

        # 26 nov 2002
        'creation': 1038229200
    },
    {
        'domain': 'irc.chatjunkies.org',
        'afs': [IP4],

        # 28 june 2002
        'creation': 1025186400
    },
    {
        'domain': 'irc.dosers.net',
        'afs': [IP4],

        # 20 may 2020
        'creation': 1590501600
    },
    {
        'domain': 'irc.entropynet.net',
        'afs': [IP4, IP6],

        # 11 sep 2011
        'creation': 1312984800
    },
    {
        'domain': 'irc.liberta.casa',
        'afs': [IP4, IP6],

        # 7 feb 2020
        'creation': 1580994000
    },
    {
        'domain': 'irc.financialchat.com',
        'afs': [IP4],

        # 1 aug 2002
        'creation': 1028210400
    },
    {
        'domain': 'irc.irc2.hu',
        'afs': [IP4],

        # 4 jan 2004
        'creation': 1073134800
    },
    {
        'domain': 'irc.phat-net.de',
        'afs': [IP4, IP6],

        # 6 nov 2000
        'creation': 975848400
    },
    {
        'domain': 'irc.slacknet.org',
        'afs': [IP4, IP6],

        # 20 aug 2000
        'creation': 966434400
    },
    {
        'domain': 'irc.tweakers.net',
        'afs': [IP4, IP6],

        # 30 apr 2002
        'creation': 1020088800
    },
]

# Sort servers by creation date (oldest first.)
irc_servers = sorted(irc_servers, key=lambda k: k['creation'])

# Create server lists by af.
IRC_SERVERS = {
    IP4: [s for s in irc_servers if IP4 in s['afs']],
    IP6: [s for s in irc_servers if IP6 in s['afs']],

}
