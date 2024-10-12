Hyper-usable HTTP client
==========================

In my opinion one design that absolutely nailed building services
for the web was PHP so I built a client that takes inspiration from that.
First lets start with a basic GET request.

.. literalinclude:: ../../examples/example_14.py
    :language: python3

The above code shows how you can send $_GET params to a website.
Loosely speaking: the vars method is where $_GET and $_POST go.
There is a get, post, and delete method that cause these
HTTP actions to occur. Here's an example for POST:

.. literalinclude:: ../../examples/example_15.py
    :language: python3

The design of this HTTP client results in copies of the objects
properties being made for each call. This helps to encapsulate
information and makes debugging a breeze. The return value of an API
call is a new copy of the client with additional
properties like a pipe, output, and more.

The HTTP client also supports custom HTTP headers. You can control
underlying socket parameters with more detail by passing in a custom
NET_CONFIG dictionary to the get, post, and delete methods. This
structure is detailed at the bottom here: :doc:`here.<../general/pipes>`

.. code-block:: python

    class WebCurl():
        def __init__(self, addr, throttle=0, do_close=1, hdrs=[]):
            """
            throttle = a second timeout to delay a request by.
            do_close = whether or not the underlying pipe is closed (
                useful if you're streaming data and such.)
            hdrs = Custom HTTP request headers e.g.:
                [[b"user-agent", b"toxiproxy-cli"]]
            """
        #
        async def get(self, path, hdrs=[], conf=NET_CONF):
            pass
        #
        #...

