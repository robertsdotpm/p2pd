from p2pd import *

async def do_stuff():
    #netifaces = await Netifaces().start()
    print(netifaces.interfaces())
    if_name = netifaces.interfaces()[0]
    print(netifaces.ifaddresses(if_name))
    
    return
    i = await Interface(if_name).start()
    print(i)

async_test(do_stuff)