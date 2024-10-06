Lightweight web framework
===========================

If you're a Python developer you may have used popular web frameworks like Flask or Django.
These projects can be complex and require many third-party dependencies to run. What's interesting about Python is that it's
standard library already includes everything you need for a web framework.
It's just not that well documented.

For example: there's code that will process a HTTP request, parse URLs, and more.
What I've done is wrap these components in an interface similar to flask with P2PD
for the networking. The result is a light-weight, async web framework, that properly
supports multiple interfaces, address families, and transports.

.. literalinclude:: ../../examples/example_16.py
    :language: python3

As you can see functions in the web framework are decorated with a REST method.
They use async await, a pipe back to the client, and introduce a v parameter --
with access to relevant HTTP information. The structure of v looks like this:

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

When you define your REST methods you can have a list of named arguments.
These highlight what is added by name in a URL. For example: '/cat/meow' could
be highlighted with @RESTD.GET(["cat"]) and 'name' would be {'cat': 'meow'}.
Values in the URL path that aren't matched by named paths are added
to an indexed dictionary (at keys 0 ... to len - 1.)

The field 'body' is the binary content of a POST request. While req is a class
that has processed the HTTP request of the client. There's fields are useful 
for debugging server code.