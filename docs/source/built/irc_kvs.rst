A key-value store over IRC
=============================

Web browsers and networked applications rely critically on domain names
to avoid people having to remember long strings of numbers. Without domain
names its unlikely the Internet would have been as successful as it was.
Unfortunately, the domain name system is commercial and lacks a standardized
protocol for registering domains between providers. Such a system is necessary
for peer-to-peer software because programs need to be able to register names
for themselves without humans having to baby sit them and the names ought to
not be paid so accessibility is granted to these software programs.

The question is: how to accomplish this in such a way that it would run on public
infrastructure. To my knowledge there are no existing systems that offer the
equivalent of a permissioned, open, key-value store. I have researched the
question and tried many prototypes to try solve this problem - without much luck.
Chat-GPT seems to think that such a system doesn't exist. So I built one.

My system implements a distributed key-value store across IRC servers.
I use channel names as key-names and channel topics as key-values. Names
are stored by ensuring that a minimum number of channels can be registered
for a single name. This allows people to lookup names and know that
after they get more than the maximum registration failure number
they can be reasonably certain that the results point to the right name.
This helps to maintain integrity if servers go down, avoids name conflicts,
and provides a higher level of security than trusting one server.

.. code-block:: python

    import hashlib
    from p2pd import *

    async def example():
        # Save your seed value somewhere.
        seed = hashlib.sha3_256(b"Use a secure password and save it in a password manager.")

        # Load a network interface.
        interface = await Interface()

        # Start the KVS.
        irc_kvs = await IRCDNS(
            i=interface,
            seed=seed,
            servers=IRC_SERVERS
        ).start()
        refresher = IRCRefresher(irc_kvs)

        # Register a new name.
        # To require a password you can use:
        # ["example", ".cawm", "my super secret passwrod"]
        name_info = ["example", ".cawm"]
        await irc_kvs.name_register(*name_info)

        # Store a value for that name.
        await irc_kvs.store_value(*["I liek the cat"] + name_info)

        # Get back that value.
        val = await irc_kvs.name_lookup(*name_info)["msg"]

        # Cleanup (this closes local database and cons.)
        await irc_kvs.close()

You can see from this example that a cryptographic seed is generated using
a password as an input to a hash function. Make sure the bytes used for
the seed are at least 24 bytes long.

.. warning::
    Since IRC networks have expiries for inactive nicknames and channels. If you call await refresher.refresher() it will handle refreshing
    everything and even attempt to register names that may
    have failed (up to a certain threshold.)