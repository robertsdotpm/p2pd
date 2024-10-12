Queues
========

If you want to use the push / pull APIs there are some details
you might find useful. In order to support these APIs the
software must be able to save messages. It does this by using queues.
Each queue may be indexed by a message regex and an
optional tuple for a reply address.

These queues only exist when a subscription is made. **By default P2PD
subscribes to all messages when a destination is provided for a pipe and
so does the REST API.**

Why use message subscriptions?
--------------------------------

You may know already that UDP offers no delivery guarantees. What this means is most UDP
protocols (like STUN) end up using randomized IDs in
requests / responses as kind of an asynchronous form of 'ordering.'
There is also the case of UDP being 'connectionless.' This means
you can have a single socket send packets to many destinations.

What ends up happening is you get messages [on the same socket] that:

    1. **... Are from different hosts and or ports.**
    2. **... Match different requests.**

So I had the idea of being able to sort messages into queues.
Such an approach is flexible and is already used by the STUN client.
Here's what that looks like in practice.

Javascript subscription example
--------------------------------

The REST server bellow is based on the module here: :doc:`/built/rest_api`

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
            "/sub/con_name/name/sub_name/msg_p/" + msg_p, //+ "addr_p" + addr_p,
            "/send/con_name/" + en("long_p2pd_test_string_abcd123"),
            "/recv/con_name/name/sub_name", // + "addr_p" + addr_p,
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

    p2pd_test();

.. code-block:: javascript

    // Subscribe.
    {
        "error": 0,
        "name": "con_name",
        "sub": "[b'test', None]"
    }

    // Send data.
    {
        "error": 0,
        "name": "con_name",
        "sent": 29
    }

    // Receive data.
    {
        "client_tup": [
            "192.168.21.8",
            10062
        ],
        "con_name": "con_name",
        "data": "p2pd test string\r\n\r\n",
        "error": 0
    }


The URL encode method is used to make the data 'safe' to pass in a URL.
A subscription consists of a msg regex and an optional tuple matching
a reply address of the client. IPs get normalized so IPv6 addresses
are expanded. You can specify 'from any port' if you set the port to 0.

The regex method used with the message regex is 'find_all' so any
instance of the pattern returns a match. You can always use the caret
^ and dollar $ characters to match a whole string

.. HINT::
    Checkout https://regex101.com/ if you need help with your regexes!

Python subscription example
-----------------------------

This example shows what subscriptions look like
from Python.

.. literalinclude:: ../../examples/example_7.py
    :language: python3

Final conclusions
----------------------

Messages are delivered to every matching subscription queues. If you subscribe to
a specific pattern / tup you may end up with copies of every message because by
default pipes with a destination subscribe to all messages. To unsubscribe
from all messages:

.. code-block:: python

    pipe.unsubscribe(SUB_ALL)

.. code-block:: shell

    curl -X DELETE "http://localhost:12333/sub/con_name/name/all"

.. code-block:: javascript

    async function p2pd_test(server) 
    {
        var out = await $.ajax({
            url: "http://localhost:12333/sub/con_name/name/all",
            type: 'DELETE',
            dataType: "text"
        });

        console.log(out);
    }

.. code-block:: javascript

    {
        "error": 0,
        "name": "con_name",
        "unsub": "[None, None]"
    }
