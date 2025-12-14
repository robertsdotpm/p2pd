import uuid
from p2pd import *

class TestHelloWorld(unittest.IsolatedAsyncioTestCase):
    async def test_hello_world(self):
        print("hello")