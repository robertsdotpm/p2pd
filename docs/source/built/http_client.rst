Hyper-usable HTTP client
==========================

When I built my own REST framework it's been necessary to also build
a basic HTTP client. The reason I've done this is I wanted the client
to be compatible with the existing capabilities this software offers
like being able to easily leverage multiple network interfaces and
utilize the external addresses they have access to.

In my opinion one design that absolutely nailed building services
for the web was PHP so my HTTP client takes inspiration from that.
First lets start with a basic GET request.

.. literalinclude:: ../python/examples/example_14.py
    :language: python3

The above code shows how you can send $_GET params to a website.
Loosely speaking: the vars method is where $_GET and $_POST go.
There is a method for get, post, and delete that cause such
HTTP methods to occur. Here's an example for POST:

.. literalinclude:: ../python/examples/example_15.py
    :language: python3

The design of this HTTP client results in copies of the objects
properties being made for each call. This helps to encapsulate
information and makes debugging a breeze. The return value of an API
call is literally a new copy of the client but with additional
properties like pipe, out, and info - try exploring these fields!

The HTTP client also supports custom HTTP headers. You can control
underlying socket parameters with more detail by passing in a custom
NET_CONFIG dictionary to the get, post, and delete methods. This
structure is detailed at the bottom here: :doc:`here.<../python/pipes>`

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

