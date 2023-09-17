from p2pd.test_init import *
from p2pd import *
import re

"""
All of the Python code used in the documentation gets tested
using this module. Easy to know if examples still work.
"""

EXAMPLES_DIR = "../docs/source/python/examples"

class TestPyExamples(unittest.IsolatedAsyncioTestCase):
    async def do_py_example(self, n):
        print(n)
        with open(f"{EXAMPLES_DIR}/example_{n}.py") as fp:
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
                print(f"Py example {n} failed.")
                what_exception()
                assert(0)

            # Run the async callback.
            coro = globals().get("example")
            await coro()

        log(f"py example {n} passed")

    # So they can be tested concurrently.
    async def test_1(self):
        await self.do_py_example(1)

    async def test_2(self):
        await self.do_py_example(2)

    async def test_3(self):
        await self.do_py_example(3)

    async def test_4(self):
        await self.do_py_example(4)

    async def test_5(self):
        await self.do_py_example(5)

    async def test_6(self):
        await self.do_py_example(6)

    async def test_7(self):
        await self.do_py_example(7)

    async def test_8(self):
        await self.do_py_example(8)

    async def test_9(self):
        await self.do_py_example(9)

    async def test_10(self):
        await self.do_py_example(10)

    async def test_11(self):
        await self.do_py_example(11)

    async def test_12(self):
        await self.do_py_example(12)

    async def test_13(self):
        await self.do_py_example(13)

    async def test_14(self):
        await self.do_py_example(14)

    async def test_15(self):
        await self.do_py_example(15)
    

if __name__ == '__main__':
    main()