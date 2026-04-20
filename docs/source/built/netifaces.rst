Portable netifaces
===================

In Python the PyPI module `netifaces <https://pypi.org/project/netifaces/>`_ is a popular package for retrieving information on network interface cards. However, on Windows it has a few problems:

1. It requires the .NET Framework.
2. It does not use proper names for interfaces (GUIDs are used instead of friendly names on Windows.)

Additionally, some information is incorrect or missing, including the interface index number (needed on Windows), MAC address, and some subnet mask fields.

P2PD depends on `aionetiface <https://pypi.org/project/aionetiface/>`_ which provides a fixed wrapper around the original netifaces module. It has the same API as netifaces so it can be used as a drop-in replacement (it uses command-line calls internally and must be run inside an async event loop.)

.. literalinclude:: ../../examples/portable_netifaces.py
    :language: python3
