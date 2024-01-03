Examples
=========

Here is a collection of example(s) that use P2PD in some form.

REST APIs
-----------

There exists various Python frameworks for building REST APIs. But
what many people don't realize is the Python standard library already
supports enough of HTTP that a library isn't often isn't required.
Python is able to parse HTTP requests and responses into objects
that are quite easy to use - though the location of these features 
in the standard library isn't that intuitive.

I've built a simple module that accesses these features. Using this
module you can now easily build a TCP / UDP / IPv4 / IPv6 async
REST API in Python. Here's an example of that.

.. literalinclude:: examples/example_13.py
    :language: python3