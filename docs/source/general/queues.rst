Queues
========

If you want to use the push / pull APIs there are some details
you might find useful. In order to support these APIs the
software must be able to save messages. It does this using queues.
Each queue may be indexed by a message regex and a
optional tuple for a reply address.

These queues only exist when a subscription is made. **By default P2PD
subscribes to all messages when a destination is provided for a pipe and
so does the REST API.**

Why use message subscriptions?
--------------------------------

You may know already UDP offers no ordered delivery or indeed any
reliable delivery guarantee at all. What this means is most UDP
protocols (like STUN) end up using randomized IDs in
requests / responses as kind of an asynchronous form of 'ordering.'
There is also the case of UDP being 'connectionless.' This means
you can have a single socket send packets to many destinations.

What ends up happening is you get messages [on the same socket] that:

    1. **... Are from different hosts and or ports.**
    2. **... Match different requests.**

So I had the idea of being able to sort messages into queues.
Such an approach is flexible and is already used by my STUN client.
Here's what that looks like in practice.

Javascript subscription example
--------------------------------

.. code-block:: javascript

    en = encodeURIComponent;
    async function p2pd_test(server) 
    {
        // Do these in order to test some P2PD APIs.
        msg_p = en("test");
        //addr_p = en("('127.0.0.1', 0)"); 0 == any port.
        var paths = [
            "/version",
            "/open/con_name/self",
            "/sub/con_name/msg_p/" + msg_p, //+ "addr_p" + addr_p,
            "/send/con_name/" + en("long_p2pd_test_string_abcd123"),
            "/recv/con_name/sub_index/", // + "addr_p" + addr_p,
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
            
            if(out.hasOwnProperty("index"))
            {
                paths[4] += out["index"].toString();
            }

            console.log(out);
        }
    }

.. code-block:: javascript

    // Subscribe.
    {
        "error": 0,
        "name": "con_name",
        "sub": "[b'[hH]e[l]+o', None]"
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