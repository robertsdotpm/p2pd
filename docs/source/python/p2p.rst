Peer-to-peer connections
===========================

| **Let's start with how to connect to another peer.**

The code has two functions that simulate what two different computers might
run (**computer_a** and **computer_b**.) Since it is usually impractical
for people to directly remember IP address information names are used instead.
Here the naming solution is provided by 'IRCDNS' - a permissioned, key-value
store that P2PD provides running on IRC infrastructure.

.. literalinclude:: examples/example_1.py
    :language: python3

If you use 'IRCDNS' to name your node the first thing to understand is the seed. Seeds are 24 or more cryptographically random bytes (such as from
secrets.token_bytes() or from hashlib.sha3_256) that is used to
generate your account details on IRC networks. Your account details
let you register and update names so you should save your seed!

Names consist of three parts. The main name, the TLD, and an optional password.
For example: ['my awesome name', 'cats', ''] represents 'my awesome name' on the
'cats' TLD with no password. You can point a name to your P2P address by
passing that list to the register call for the node object. Otherwise,
you can set a name to any value node.irc_dns.name_register(value, name, tld, pw) to use a name for a different purpose.

.. warning::
    IRC networks don't allow you to keep nick names and channels
    forever and this means periodically checking for expiry.
    I have written the function to handle this all automatically
    but you will need to call it yourself for now.
    (say every day or so -- await node.name_refresher()).
