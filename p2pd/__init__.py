
import sys

"""
This is a hack to avoid double-imports of a module when using
the -m switch to run a module directly. Python modules are lolz.
"""
if not '-m' in sys.argv:
    from .do_imports import *

from .utils import p2pd_setup_event_loop

p2pd_setup_event_loop()

__version__ = '2.7.9'

