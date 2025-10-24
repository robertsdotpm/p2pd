
import sys


"""
This is a hack to avoid double-imports of a module when using
the -m switch to run a module directly. Python modules are lolz.
"""
if not '-m' in sys.argv:
    from .do_imports import *

from .entrypoint import *


__version__ = '2.7.9'

