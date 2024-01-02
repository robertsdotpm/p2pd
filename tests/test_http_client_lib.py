import uuid
from p2pd.test_init import *
from p2pd.http_client_lib import *


asyncio.set_event_loop_policy(SelectorEventPolicy())


class TestHTTPClientLib(unittest.IsolatedAsyncioTestCase):
    # Should break as chunked is not supported.
    async def test_incomplete_read(self):
        has_thrown = False
        try:
            reply = b"""HTTP/1.1 200 OK\r\nDate: Sun, 23 Jul 2023 02:33:16 GMT\r\nContent-Type: text/html; charset=UTF-8\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nServer: awex\r\nX-Xss-Protection: 1; mode=block\r\nX-Content-Type-Options: nosniff\r\nX-Request-ID: c63f58e18f3344aa27bfc3646ea7d7aa\r\n\r\n1\r\n1\r\n"""
            resp = ParseHTTPResponse(reply)
            out = resp.out()
        except:
            has_thrown = True

        assert(has_thrown)
        
if __name__ == '__main__':
    main()