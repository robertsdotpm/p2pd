from p2pd import *

class CustomServer(RESTD):
    @RESTD.GET()
    async def show_index(self, v, pipe):
        print(v)
        
        # text/html response.
        return "hello"
    
    @RESTD.POST(["proxies"], ["toxics"])
    async def add_new_toxic(self, v, pipe):
        """
        Matches /proxies/.*/toxics/.*
        and names the value at 
        v['proxies'] and v['toxics']
        respectively.
        """
        
        # Demonstrates a JSON response.
        return {
            "status": "success"
        }
    
    @RESTD.DELETE(["proxies"], ["toxics"])
    async def del_new_toxic(self, v, pipe):
        # Application/octet-stream response.
        return b""

async def example():
    nic = await Interface()
    server = CustomServer()
    await server.listen_loopback(TCP, 60322, nic)
    
    """
    Feel free to add a while: sleep
    then test it with CURL or something...
    """
    await server.close()

if __name__ == '__main__':
    async_test(example)