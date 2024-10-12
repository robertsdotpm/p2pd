More portable netifaces
=========================

In Python the PyPI module 'netifaces' is a popular project for retrieving information on network cards. However, on Windows it has a few problems:

1. It requires the .NET Framework.
2. It does not use proper names for interfaces (GUIDs are used on Windows.)

Additionally, pieces of information are incorrect or missing. Such as the interface number (needed on Windows), MAC address, and some subnet mask fields.

I've provided a wrapper around the original module to address these problems. It has the same interface as netifaces so it can be used as a drop-in replacement (it does make command-line calls and hence needs to be ran inside an event loop.)

.. literalinclude:: ../../examples/portable_netifaces.py
    :language: python3

More information on netifaces here: https://pypi.org/project/netifaces/