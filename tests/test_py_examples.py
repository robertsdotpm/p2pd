from p2pd.test_init import *
from p2pd import *
import re

"""
All of the Python code used in the documentation gets tested
using this module. Easy to know if examples still work.
"""

EXAMPLES_DIR = "../docs/source/python/examples"

class TestPyExamples(unittest.IsolatedAsyncioTestCase):
    async def test_py_examples(self):
        for no in range(1, 13 + 1):
            print(no)
            with open(f"{EXAMPLES_DIR}/example_{no}.py") as fp:
                py_code = fp.read()

                # Event loop is already running so replace
                # async_test with an await call.
                py_code = py_code.replace(
                    'async_test(example)',
                    'pass'
                )

                # Load the example code definitions.
                try:
                    exec(py_code, globals())
                except Exception as e:
                    print(f"Py example {no} failed.")
                    what_exception()
                    assert(0)

                # Run the async callback.
                coro = globals().get("example")
                await coro()

            log(f"py example {no} passed")

        await asyncio.sleep(.25)

if __name__ == '__main__':
    main()