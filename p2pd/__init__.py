
import sys

"""
This is a hack to avoid double-imports of a module when using
the -m switch to run a module directly. Python modules are lolz.
"""
if not '-m' in sys.argv:
    from .do_imports import *
    multiprocessing.set_start_method("spawn")
    asyncio.set_event_loop_policy(SelectorEventPolicy())

__version__ = '2.7.9'

