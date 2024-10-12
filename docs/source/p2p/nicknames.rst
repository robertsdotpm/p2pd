Nicknames
============

Your P2P node has an address that lists information on your network
interface cards and meta data useful for encrypted communication.
The address is very long. Similar, to an IP addresses, so that
working with them directly can be cumbersome. You can imagine having to read
many numbers to a friend and hoping they enter them correct. Fortunately,
P2PD has a simple solution: nicknames.

Nicknames give you the ability to give your node a short memorable name. The name can then be easily shared and used to lookup
your nodes address information. What's cool about this system is it requires no registration to use. Instead, there's a fixed limit
of names that can be registered per IP address and the limit acts as a queue.

.. image:: ../../diagrams/nicknames.png
    :alt: Diagram of the nickname system in P2Pd

Above you can see the process of registering a name. It involves creating
ECDSA keys for signing operations that create / update names; Making
HTTP requests to name servers; and seeing if your request succeeded.
Actually, names in P2PD have a second part appended -- a TLD --
that identifies the sub-set of name servers that store the name on.
The TLD is calculated based on the responses received when registering a name (success or not.)
Though the software automates this part for you.

.. literalinclude:: ../../examples/node_with_nickname.py
    :language: python3

Another peer can then use your node's nickname in a connect call.
**Note: that whatever name you pass to nickname isn't the full
name that you need to share.** The function returns the full name
which has a TLD appended to it. E.g. "name.peer"