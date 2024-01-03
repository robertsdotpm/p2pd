Using P2PD from Python
========================

**Running async examples**

Alr1ght people, P2PD uses Python's 'asynchronous' features to run
everything in an event loop. You might want to use the special 'REPL'
that the asyncio module provides to run these examples. It's available
on (very) recent versions of Python like 3.8 or higher. Otherwise,
P2PD has a function called async_test(name_of_async_func, arg_tup)
that can be used to run async code.

.. code-block:: shell

    python3 -m asyncio

.. code-block:: python3

    asyncio REPL 3.11.0
    Use "await" directly instead of "asyncio.run()".
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import asyncio
    >>> from p2pd import *

Now you can simply type `await some_function()` in the REPL to execute it.
If you experience errors in the REPL you'll have to use a regular Python
file for the examples.

**Before we get started all example code assumes that:**

    1. The 'selector' event loop is being used.
    2. The 'spawn' method is used as the multiprocessing start method.
    3. You are familiar with how to run asynchronous code.
    4. The string encoding is "UTF-8."

This keeps the code consistent across platforms. The package sets
these by default so if your application is using a different configuration
it may not work properly with P2PD.


.. toctree::
    basics
    pipes
    queues
    daemons
    p2p
    examples
