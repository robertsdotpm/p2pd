from .net import *

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
