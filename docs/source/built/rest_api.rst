The P2PD REST API
==================

Starting the server
--------------------

Start the REST API server::
   python3 -m p2pd.rest_api

Running this command will start the server on http://127.0.0.1:12333/
The server has no password and will only allow requests from
an 'origin' of 127.0.0.1 or null. The null origin occurs when
a HTML document is opened locally. If a website you visit tries
to use the P2PD API your browser will include the domain name as
an origin which the server will reject.

Making your first request
---------------------------

To check the server you can visit the version resource.

.. code-block:: shell

   curl http://localhost:12333/version

You should see a JSON response.

.. code-block:: javascript

   {
      "author": "Matthew@Roberts.PM",
      "title": "P2PD",
      "version": "0.1.0"
   }

Looking up your peer's address
-------------------------------

You'll want to know how to get your peers address. The address is
used to try connect to a peer.

.. code-block:: shell

   curl http://localhost:12333/p2p/addr

Sample JSON response.

.. code-block:: javascript

   {
      "addr": "[0,1.3.3.7,192.168.21.21,58959,3,2,0]-0-looongcatislong",
      "error": 0
   }

Now lets try connect to it
---------------------------

Peer addresses will be passed to the 'open' resource. A number of strategies
are used to try establish connections. The order of success will define
how fast connections can be opened.

.. code-block:: shell

   curl "http://localhost:12333/p2p/open/name_for_new_con/addr_of_node"

Please note how the connection is given a name. The name is used to identify
connections rather than using IDs. You will need to remember names
for later API calls. Should you wish to test P2P connections you can
also use 'self' to connect to yourself.

.. code-block:: shell

   curl http://localhost:12333/p2p/open/con_name/self

The JSON response shows information on the new connection.

.. code-block:: javascript

   {
      "fd": 1060,
      "if": {
         "name": "Intel(R) Wi-Fi 6 AX200 160MHz"
         "offset": 0
      },
      "laddr": [
         "192.168.21.21",
         58537
      ],
      "name": "con_name",
      "raddr": [
         "192.168.21.21",
         58959
      ],
      "route": {
         "af": 2,
         "ext_ips": [
               {
                  "af": 2,
                  "cidr": 32,
                  "ip": "1.3.3.7"
               }
         ],
         "nic_ips": [
               {
                  "af": 2,
                  "cidr": 32,
                  "ip": "192.168.21.21"
               }
         ]
      },
      "strategy": "direct connect"
   }

You can see the information includes details like the file descriptor
number of the socket, your external address for the socket, and
the technique that worked to establish the connection.

Text-based send and receive
-----------------------------

Let's start with something simple. For these examples I'll assume you
want to work with a simple text-based protocol. In reality you may be
building something far more complex and require more flexibility
but this is a good starting point.

**Sending text:**

The node server has a built-in echo server. We'll be using this
protocol to test out some commands.

.. code-block:: shell

   curl "http://localhost:12333/p2p/send/con_name/ECHO%20hello,%20world!"

.. code-block:: javascript

   {
      "error": 0,
      "name": "con_name",
      "sent": 18
   }

**Receiving text:**

.. code-block:: shell

   curl "http://localhost:12333/p2p/recv/con_name"

.. code-block:: javascript

   {
      "data": "hello, world!",
      "error": 0,
      "client_tup": [
         "192.168.21.200",
         54925
      ]
   }

Binary send and receive
-------------------------

So far all API methods have used the GET method. GET is ideal for regular,
text-based data where you don't have to worry too much about encoding.
But if you want a more flexible approach that can also deal with binary
data it's necessary to visit the POST method. These next examples
will be written in Javascript using the Jquery library.

.. code-block:: javascript

   async function binary_push()
   {
      // Binary data to send -- outside printable ASCII.
      // Will send an echo request to the Node server.
      var x = new Uint8Array(9);
      x[0] = 69; // 'E'
      x[1] = 67; // 'C'
      x[2] = 72; // 'H'
      x[3] = 79; // 'O'
      x[4] = 32; // ' '
      x[5] = 200; // ... binary codes,
      x[6] = 201;
      x[7] = 202;
      x[8] = 203;

      // Send as encoded binary data using POST to API.
      // This demonstrates that binary POST works.
      var url = 'http://localhost/p2p/binary/con_name';
      var out = await $.ajax({
         url: url,
         type: "POST",
         data: x,    
         contentType: "application/octet-stream",
         dataType: "text",
         processData: false
      });
   }

.. code-block:: javascript

   {
      "error": 0,
      "name": "con_name",
      "sent": 9
   }

Here's what it looks like to receive the binary back again.

.. code-block:: javascript

   async function binary_pull()
   {
      // Receive back binary buffer.
      // Node server should echo back the last 4 bytes.
      var url = 'http://localhost/p2p/binary/con_name';
      out = await $.ajax({
         url: url,
         type: 'GET',
         processData: 'false',
         dataType: 'binary',
         xhrFields:{
            responseType: 'blob'
         },
         headers: { 'X-Requested-With': 'XMLHttpRequest' }
      });

      // Convert output blob to array buffer.
      // Then convert that to a Uint8Array.
      mem_view = await out.arrayBuffer();
      out_bytes = new Uint8Array(mem_view);
   }

By the way: these examples use el8 async await syntax. This avoids callback
hell which is low IQ. If you don't understand async-style code it's time
for you to learn! All code in P2PD is async.

Bidirectional relay pipes
--------------------------

Theses simple send/receive calls are examples of push and pull APIs. In
other words -- its up to you to check whether messages are available.
Such an approach might be fine for simple scripts but it's a
little inefficient having to constantly check or 'poll' for new
messages. Fortunately, P2PD has you covered. There is a special API
method that converts a HTTP connection into a two-way relay.

What I mean by this is if you make a HTTP request to a named
connection P2PD will relay data you send to that connection
to the named connection and back again. This is very useful because
it allows you to write asynchronous code that only has to handle data
when it's available. Almost like a regular connection you made yourself.

The catch is I can't write the code for you exactly as
I don't know what language you'll be using with the API -- but
so long as you know how to make a connection and send a HTTP request
the process is quite straight-forwards.

1. Make a **SOCK_STREAM** socket. Choose **AF_INET** for the address
   family.
2. Connect the socket to **localhost** on port **12333**.
3. Send a HTTP GET request to /p2p/pipe/con_name. Data to send:

.. code-block:: text

   GET /p2p/pipe/con_name HTTP/1.1\r\n
   Origin: null\r\n\r\n

The connection is closed on error. You can test it works by
sending 'ECHO hello world' down the connection and checking for
the response. As this is a relay between an associated connection
to a peer's node server which implements echo.

Publish-subscribe
------------------

To learn about how to use the REST API for topic filtering please read the :doc:`/general/queues` page.