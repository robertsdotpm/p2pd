The P2PD REST API
==================

Starting the server
--------------------

Start the REST API server::
   python3 -m p2pd.rest_api

Running this command will start the server on localhost:12333
The server has no password and will only allow requests from
an 'origin' of 127.0.0.1 or null. The null origin occurs when
a HTML document is opened locally. If a website you visit tries
to use the P2PD API your browser will include the domain name as
an origin which the server will reject.

Making your first request
---------------------------

To check the server you can visit the version resource.

.. parsed-literal:: 
   curl `<http://localhost:12333/version>`_

You should see a JSON response.

.. code-block:: javascript

   {
      "author": "Matthew@Roberts.PM",
      "title": "P2PD",
      "version": "3.0.0"
   }

Looking up your peer's address
-------------------------------

You'll want to know how to get your peers address. The address is
used to connect to a peer.

.. parsed-literal:: 
   curl `<http://localhost:12333/addr>`_ 

Sample JSON response.

.. code-block:: javascript

   {
      "addr": "[0,1.3.3.7,192.168.21.21,58959,3,2,0]-0-looongcatislong",
      "error": 0
   }

Now lets try connect to it
---------------------------

Peer addresses will be passed to the 'open' resource. A number of strategies
are used to establish connections. The order of success will define
how fast connections can be opened.

.. parsed-literal:: 
   curl `<http://localhost:12333/open/name_for_new_con/addr_of_node>`_

Please note how the connection is given a name. The name is used to identify
connections rather than using IDs. You will need to remember names
for later API calls. Should you wish to test P2P connections you can
also use 'self' to connect to yourself.

.. parsed-literal:: 
   curl `<http://localhost:12333/open/con_name/self>`_

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
   }

You can see the information includes details like the number of the socket, your external address, the interface the connection
belongs to, and so on.

Text-based send and receive
-----------------------------

Let's start with something simple. For these examples I'll assume you
want to work with a simple text-based protocol. In reality you may be
building something more complex and require more flexibility
but this is a good starting point.

**Sending text:**

The node server has a feature for echoing back a fixed string
if the right sequence of bytes occur. We'll be using this
feature to test out some commands.

.. parsed-literal:: 
   curl `<http://localhost:12333/send/con_name/long_p2pd_test_string_abcd123>`_

.. code-block:: javascript

   {
      "error": 0,
      "name": "con_name",
      "sent": 18
   }

**Receiving text:**

.. parsed-literal:: 
   curl `<http://localhost:12333/recv/con_name>`_

.. code-block:: javascript

   {
      "data": "got p2pd test string",
      "error": 0,
      "client_tup": [
         "192.168.21.200",
         54925
      ]
   }

Binary send and receive
-------------------------

So far all API methods have used HTTP GET. GET is ideal for 
text-based data where you don't have to worry about encoding.
But if you want to support arbitrary data it's necessary to
use the POST method. The following JS examples require jQuery.

.. code-block:: shell

   curl -H 'Content-Type: application/octet-stream' -d 'long_p2pd_test_string_abcd123' -X POST "http://localhost:12333/binary/con_name"

.. code-block:: javascript

   async function binary_push()
   {
      // Binary data to send (this could represent non-ASCII.)
      // The encoder is used to covert it into uint8s.
      var enc = new TextEncoder();
      var enc_str = enc.encode("long_p2pd_test_string_abcd123");

      // Copy encoded string into Uint8 buffer.
      // Thank you chat-gpt. Never knew how to do this before.
      var buf = new Uint8Array(29);
      buf.set(enc_str);

      // Send as encoded binary data using POST to API.
      // This demonstrates that binary POST works.
      var url = 'http://localhost:12333/binary/con_name';
      var out = await $.ajax({
         url: url,
         type: "POST",
         data: buf,    
         contentType: "application/octet-stream",
         dataType: "text",
         processData: false
      });

      // Show the output in the console.
      console.log(out);
   }

.. code-block:: javascript

   {
      "error": 0,
      "name": "con_name",
      "sent": 29
   }

Here's what it looks like to receive the binary back again.

.. parsed-literal:: 
   curl `<http://localhost:12333/binary/con_name>`_

.. code-block:: javascript

   async function binary_pull()
   {
      // Receive back binary buffer.
      // Node server should send back a test string.
      var url = 'http://localhost:12333/binary/con_name';
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

Bidirectional relay pipes
--------------------------

Theses simple send/receive calls are examples of push and pull APIs. In
other words -- its up to you to check whether messages are available.
Such an approach might be fine for simple scripts but it's a
little inefficient having to constantly check or 'poll' for new
messages. For the REST API there is another neat option: a special API
method that converts HTTP connections into two-way relays.

What I mean by this is if you make a HTTP request to a named
connection P2PD will relay data you send to that connection
to the named connection and back again. This is very useful because
it allows you to write asynchronous code that only has to handle data
when it's available. Almost like a regular connection you made yourself.

1. Make a **SOCK_STREAM** socket.
2. Connect the socket to **localhost** on port **12333**.
3. Send a HTTP GET request to /tunnel/con_name. Data to send:

.. code-block:: text

   GET /tunnel/con_name HTTP/1.1\r\n
   Origin: null\r\n\r\n

The connection is closed on error. You can test it works by
sending 'long_p2pd_test_string_abcd123' down the connection and checking for the test string response. What results is a relay between a named P2P connection (handled by the peers
protocol handlers.)

Publish-subscribe
------------------

To learn about how to use the REST API for topic filtering please read the :doc:`/general/queues` page.