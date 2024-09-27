Queues
========

If you want to use the push and pull APIs over the relay pipes
there are some additional details that you might find useful. In order
to support pull API usage the software must be able to save messages.
It does this by using in memory queues which for now have no set limit.
What hasn't been mentioned is that these queues are organized around
subscriptions -- regex patterns that match messages and remote peers.

These queues only exist when a subscription is made. **By default P2PD
subscribes to all messages when a destination is provided for a pipe and
so does the REST API.** This has the special format of a blank message pattern
and a blank peer address pattern to match everything. The reason why this
feature exists is because of the way UDP is designed.

    **(Disclaimer: UDP really sucks.)**

You may know that UDP offers no ordered delivery or indeed any
kind of reliable delivery guarantee at all. In practice this means
that UDP-focused protocols (like STUN) end up using randomized IDs in
requests and responses as kind of an asynchronous form of 'ordering.'
There is also the case that UDP is 'connectionless.' This means that
you can have a single socket that you can use to send packets
to multiple destinations.

What ends up happening is you get back messages [on the same socket] that:

    1. **... Are from multiple different hosts and or ports.**
    2. **... Are from multiple different requests.**

And it's just a mess. So I had the idea of being able to sort messages
and remote (IP + port) tuples using regex. Such an approach is flexible
enough for any kind of protocol and is already in use in my STUN client.
Now here's what that looks like in practice. First for API then Python.

Javascript subscription example
--------------------------------

.. code-block:: javascript

    en = encodeURIComponent;
    async function p2pd_test(server) 
    {
        // Do these in order to test some P2PD APIs.
        msg_p = en("[hH]e[l]+o");
        addr_p = en("[\s\S]+");
        var paths = [
            "/version",
            "/p2p/open/con_name/self",
            "/p2p/sub/con_name/msg_p/" + msg_p + "addr_p" + addr_p,
            "/p2p/send/con_name/" + en("ECHO Hello, world!"),
            "/p2p/recv/con_name/msg_p/" + msg_p + "addr_p" + addr_p,
        ];

        // Make requests to the API.
        for(var i = 0; i < paths.length; i++) 
        {
            // Make API request.
            url = 'http://localhost:12333' + paths[i];
            var out = await $.ajax({
                url: url,
                type: 'GET',
                dataType: "text"
            });

            console.log(out);
        }
    }

.. code-block:: javascript

    // Subscribe.
    {
        "error": 0,
        "name": "con_name",
        "sub": "[b'[hH]e[l]+o', b'[\s\S]+']"
    }

    // Send data.
    {
        "error": 0,
        "name": "con_name",
        "sent": 18
    }

    // Receive data.
    {
        "data": "Hello, world!",
        "error": 0,
        "client_tup": [
            "192.168.21.200",
            54925
        ]
    }


The URL encode method is used to make the data 'safe' to pass in a URL.
A subscription consists of two regex patterns. The first regex matches
a message while the second matches an 'IP:port'. Message queues are
assigned to each subscription. When receiving messages from a queue the
full subscription / regex pair must be included. In the example above
a message pattern matches hello, Hello, helo, or Hello. The regex method
is 'find_all' so any instance of the pattern returns a match. But
you can always use the caret ^ and dollar $ characters to match a
whole string::

    Checkout https://regex101.com/ if you need help with your regexes!

Python subscription example
-----------------------------

For brevity I won't go into using the library in this section.
This is just an example to get a sense of what subscriptions look like
from Python code.

.. literalinclude:: ../../examples/example_7.py
    :language: python3

Last words on queues
----------------------

What you should understand about subscriptions and queues is messages are
delivered to all matching subscription queues. So if you subscribe to
SUB_ALL / any message and a more specific subscription you will end up
with copies of every message on the ALL queue with only the matching
messages on the second one. You may only be interested in a specific
message but if you subscribe to everything it will mean these messages
are still duplicated there. So you may have to flush messages you've
already processed should you want to use that queue.

**Recall that by default P2PD will subscribe to SUB_ALL if a pipe has a destination
set.** If you don't want to queue such messages you will have to call unsubscribe.
The way to unsubscribe is to use the delete method.

.. code-block:: shell

    curl -X DELETE "http://localhost:12333/p2p/sub/con_name/msg_p/regex/addr_p/regex"

.. code-block:: javascript

    async function p2pd_test(server) 
    {
        var out = await $.ajax({
            url: "http://localhost:12333/p2p/sub/con_name/msg_p/regex/addr_p/regex",
            type: 'DELETE',
            dataType: "text"
        });

        console.log(out);
    }

.. code-block:: javascript

    {
        "error": 0,
        "name": "con_name",
        "unsub": "[b'regex', b'regex']"
    }

By default the msg_p and addr_p are set to blank if they're not included.
Therefore to unsubscribe from 'all messages' don't include them.

.. code-block:: shell

    curl -X DELETE "http://localhost:12333/p2p/sub/con_name"

.. code-block:: javascript

    {
        "error": 0,
        "name": "con_name",
        "unsub": "[b'', b'']"
    }