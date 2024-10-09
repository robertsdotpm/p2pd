import binascii
from p2pd import *

async def example():
    # Open a UDP pipe to google's STUN server.
    pipe = await pipe_open(UDP, ("stun.l.google.com", 19302))
    
    # Random STUN message ID.
    msg_id = binascii.hexlify(rand_b(12))
    
    #  req  = req type    len     magic cookie
    req_hex = b"0001" + b"0000"  + b"2112A442"  + msg_id
    req_buf = binascii.unhexlify(req_hex)
    
    # UDP is unreliable -- try up to 3 times.
    for _ in range(0, 3):
        # Send STUN bind request and get resp.
        await pipe.send(req_buf)
        resp = await pipe.recv()
        
        # Timeout -- try again.
        if resp is None:
            continue
        
        # Show resp -- exit loop.
        print(resp)
        break
    
    # Cleanup.
    await pipe.close()

if __name__ == '__main__':
    async_test(example)