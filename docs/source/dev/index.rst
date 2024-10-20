Development
=============

Debugging mode
----------------

P2PD has a simple log file that is written to when debug mode is enabled. The
path to this log file is in the same directory that code gets executed from. To
enable debug mode use either:

.. parsed-literal:: 
    export P2PD_DEBUG=1
    set P2PD_DEBUG=1

In the terminal. The logs can then be viewed by either:

.. parsed-literal:: 
    cat program.log
    type program.log

You can filter for just the P2P messages with grep:

.. parsed-literal:: 
    cat program.log | grep p2p:

Running tests
----------------

P2PD has unit tests to check basic functionality works. These tests offer helpful
hints if individual components are working on different platforms. Though
the tests tend not to be as well maintained as the main project; Located in the
tests folder. The normal way to run them is to change to the tests directory
and run:

.. parsed-literal:: 
    python3 -m unittest

Individual files can also be run and individual tests ran by executing:

.. parsed-literal:: 
    python3 -m unittest file_name.ClassName.test_func_name

I have briefly experimented with running tests concurrently for speed. 

.. parsed-literal:: 
    python3 -m pip install -U pytest
    python3 -m pip install pytest-asyncio
    python3 -m pip install pytest-xdist
    pytest -n 8

Real world simulation
-----------------------

There is a program designed to do a real-world simulation of all parts of
the software. It is capable of simulating protocol message exchange between
nodes (with and without networking); controlling the interfaces used for a node; simulating failures; simulating node protocol replies;
and more. The program is called 'manual_test_p2p.py'.

A useful choice in this program is option 0. The code can be changed to make
a node register its address at the name servers. Then connect to that node
using whatever combination of techniques are desired. **One way to use this 
approach is you can have any device you control run manual_test_p2p
and register its name then connect to its name on another machine.**

.. parsed-literal:: 
    sig_pipe_no = number of MQTT server cons (0 for no networking)
    addr_types =
        EXT_BIND (allow external connectivity)
        NIC_BIND (allow internal connectivity)
    ifs = list of interfaces to use for nodes
    same_if = use same interface for all nodes
    multi_ifs = use multiple interfaces for nodes (only if host has them)
    use_strats = [
        P2P_DIRECT = direct connect
        P2P_REVERSE = reverse connect
        P2P_PUNCH = tcp hole punching
        P2P_RELAY = udp TURN relay
    ]

Building the docs 
--------------------

These docs use restructured text and need some dependencies to build.

.. parsed-literal:: 
    python3 -m pip install sphinx
    python3 -m pip install myst-parser
    python3 -m pip install sphinx_rtd_theme
    python3 -m pip install readthedocs-sphinx-search

The docs can be built with this command:

.. parsed-literal:: 
    cd docs
    python3 -m sphinx.cmd.build source html

Then you can open html/index.html.