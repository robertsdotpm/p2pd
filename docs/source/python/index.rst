Using P2PD from Python
========================

**Running async examples**

Alr1ght people, P2PD uses Python's 'asynchronous' features to run
everything in an event loop. The easiest way to try out examples is to
run code in an interactive prompt. For convenience P2PD includes an
interactive REPL that lets you easily run async code. It also handles
choosing the right event loop policy and multiprocessing start methods
otherwise the code wouldn't work consistently across platforms.

.. code-block:: shell

    python3 -m p2pd

.. code-block:: python3

    P2PD 2.7.9 REPL on Python 3.8 / win32
    Loop = selector, Process = spawn
    Use "await" directly instead of "asyncio.run()".
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
