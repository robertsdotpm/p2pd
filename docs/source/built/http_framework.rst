Lightweight web framework
===========================

If you're a Python developer you may have used web frameworks like Flask before.
Such frameworks are useful but usually require many
dependencies to use. What's interesting about Python is it's standard library
includes most of what you need for a web framework. What I've done is wrap these
components in a flask-like interface -- using P2PD for the networking. 

.. literalinclude:: ../../examples/example_16.py
    :language: python3

Functions in the web framework are decorated with a REST method.
Their parameters take a pipe back to the client and introduce a v parameter. The
structure of v looks like this:

.. code-block:: python

    {
        # class to process HTTP request
        # see req.url for $_GET params.
        'req': 'parsehttprequest object', 
        #
        # named REST path
        'name': {},
        #
        # unnamed positional items
        'pos': {}, # 0, 1, ... n -> value
        #
        # client remote address info
        'client': ('192.168.8.158', 60085),
        # 
        # $_POST data -- not multiple fields.
        'body': b''
    }

When you define REST methods you can have a list of named arguments.
These highlight what is named in the URL. For example: '/cat/meow' might
be highlighted with @RESTD.GET(["cat"]) and 'name' would be {'cat': 'meow'}.
Unnamed values are indexed by their position.

The field 'body' is the binary content of a POST request. While req is a class
with the processed HTTP request. These fields are useful for debugging.